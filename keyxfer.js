/* ============================================================
   carrying a key to another device

   This is QR_SECRET_TRANSFER.md — the qrst specification — under
   its `nostr-nsec` profile, and nothing else in this file knows
   what hearth is. Two devices each make a throwaway keypair, one
   shows a QR carrying its burner's public half, the other scans
   it, and everything after that travels as a NIP-59 gift wrap
   addressed to a burner. Relays see a wrap addressed to a key that
   exists for ten minutes and has never said anything else.

   Both flows are here because a person's devices do not all have
   cameras pointing the same way. In flow A the device receiving
   the key shows the QR and the device holding it scans; in flow B
   it is the other way round. They share the burners, the code, the
   message kinds and the wrap handling, so the second flow is a few
   branches rather than a second protocol.

   The code goes one way only. The device receiving the key shows
   five digits and the device holding it types them in, because a
   number that has to be carried between two screens cannot be
   passed by somebody who never looked at the second one, and two
   codes side by side with a button under them can.

   The one thing this file will not do is decide. It hands the
   screen a code to show, or a code to check, and waits: a key is
   only ever released after the person holding it says so, and only
   ever stored after the person receiving it says so.
   ============================================================ */
(function (global) {
"use strict";

const S = global.NobleSecp256k1;
const KF = global.NobleKeyFormats;

/* ---------- what is being moved (qrst §5) ----------

   The profile names the kind of secret in the code and is hashed
   into the short code itself, so two devices that disagree about
   what is moving cannot agree on a number to compare. Hearth moves
   whole identity keys and nothing else, so there is one of these
   and it is not configurable. */
const PROFILE = "nostr-nsec";

/* ---------- the relays a transfer travels over ----------

   Not the group's relay. A bothy hands a kind 1059 to its owner
   and to nobody else, and refuses a subscription naming that kind
   from anyone else at all, so a burner subscribed there would sit
   in silence until it expired. These are public relays that take
   a wrap from a key they have never seen, which is what this
   needs and what a bothy deliberately is not. Four is the most a
   QR may carry (§3.2); this list is that long so a person whose
   home connection cannot reach one of them still has three. */
const DEFAULT_RELAYS = [
  "wss://relay.damus.io",
  "wss://nos.lol",
  "wss://relay.primal.net",
  "wss://offchain.pub",
];

// qrst §11.4. Provisional rather than arbitrary: they sit in the
// ephemeral range, where relays never store them and one leaked
// unwrapped is dropped rather than kept, and they were checked free
// of collision against the registered kinds. What they are not yet
// is reserved by a NIP, so interoperability is not promised until
// that happens — but they change only if that process asks, which is
// a different thing from expecting churn.
const KINDS = {
  SEAL: 13,           // NIP-59
  GIFT_WRAP: 1059,    // NIP-59
  CLIENT_AUTH: 22242, // NIP-42, signed by the burner rather than the identity
  HELLO: 24401,
  REQUEST: 24402,
  NONCE: 24403,
  REVEAL: 24404,
  PAYLOAD: 24405,
  ACK: 24406,
  ABORT: 24407,
};

const VERSION = "1";              // the QR's v= (§11.2)
// The same number as a single byte, which is what §6 hashes. It is a
// field in the transcript rather than a suffix on the label because a
// suffix is a string two implementations can spell differently; a byte
// is not. A future version changes every digit derived here without
// anybody having to agree about punctuation.
const VERSION_BYTE = 1;
const SESSION_SECONDS = 600;      // §2, a session lives ten minutes
const WRAP_EXPIRY_SECONDS = 600;  // §11.4
const ZEROIZE_AFTER_MS = 60000;   // §7 step 18, §8 step 18
/* §13: at most three candidates held in a session. §8 also caps the
   requests a flow-B sender queues at five, and in that flow the two
   are the same set — every queued request runs its own nonce
   exchange and so becomes a candidate with a code. The tighter of
   the two is the one that satisfies both, so three is what this
   holds, in either flow. Raised with the specification's author. */
const HELD_MAX = 3;
const MAX_ATTEMPTS = 5;           // §9, code entries per session
// §9: a burner this device has already failed a code against is
// refused a second session, and three failed sessions in an hour are
// something the person is told about rather than left to notice.
const FAILURE_MEMORY_MS = 3600000;
const FAILED_SESSIONS_BEFORE_WARNING = 3;
// §11.4's SLACK, and normative rather than a choice made here: a
// rumor's own created_at is set by the other device's clock, two
// phones disagree by a minute often enough that a window with no
// give in it would throw away honest transfers, and a client that
// accepts what another rejects fails honest pairings in a way that
// looks exactly like interference.
const CLOCK_SLACK = 120;

/* ============================================================
   bytes
   ============================================================ */
const enc = new TextEncoder();

function toHex(bytes) { return S.utils.bytesToHex(bytes); }
function fromHex(hex) { return S.utils.hexToBytes(hex); }

function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function b64encode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return global.btoa(s);
}

function b64decode(text) {
  const s = global.atob(text);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// Not a promise that the bytes are gone — a JavaScript engine may
// have copied them anywhere and this cannot reach those copies.
// It clears the one array this code is holding, which is worth
// doing and is not worth describing as more than it is.
function wipe(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
}

function nowSeconds() { return Math.floor(Date.now() / 1000); }

/* ============================================================
   NIP-44 v2

   The seal and the wrap are both NIP-44 payloads, so this has to
   exist before either of them. Every primitive underneath comes
   from the vendored noble bundle; the only thing written here is
   the arrangement of them, which is what the NIP specifies.
   ============================================================ */

// HKDF-extract over the x coordinate of the ECDH point, which is
// what NIP-44 means by a conversation key: the same value on both
// sides, derived from one side's secret and the other's public.
function conversationKey(privkey, peerPubHex) {
  const shared = S.getSharedSecret(privkey, "02" + peerPubHex, true);
  return KF.extract(KF.sha256, shared.slice(1, 33), enc.encode("nip44-v2"));
}

// NIP-44's padding hides the exact length of short messages by
// rounding it up to a power-of-two-derived boundary. Everything
// this file sends is short and fixed in shape, so in practice the
// padding is doing nothing here, but a payload that skipped it
// would not be a NIP-44 payload.
function paddedLength(len) {
  if (len <= 32) return 32;
  const nextPower = 1 << (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

function pad(plaintext) {
  const bytes = enc.encode(plaintext);
  if (bytes.length < 1 || bytes.length > 65535) {
    throw new Error("nip44: plaintext out of range");
  }
  const padded = new Uint8Array(2 + paddedLength(bytes.length));
  padded[0] = (bytes.length >> 8) & 0xff;
  padded[1] = bytes.length & 0xff;
  padded.set(bytes, 2);
  return padded;
}

function unpad(padded) {
  const len = (padded[0] << 8) | padded[1];
  const text = padded.slice(2, 2 + len);
  if (len < 1 || text.length !== len || padded.length !== 2 + paddedLength(len)) {
    throw new Error("nip44: bad padding");
  }
  return new TextDecoder().decode(text);
}

function messageKeys(convKey, nonce) {
  const keys = KF.expand(KF.sha256, convKey, nonce, 76);
  return {
    chachaKey: keys.slice(0, 32),
    chachaNonce: keys.slice(32, 44),
    hmacKey: keys.slice(44, 76),
  };
}

function nip44Encrypt(plaintext, convKey, nonce) {
  const n = nonce || S.utils.randomBytes(32);
  const k = messageKeys(convKey, n);
  const ciphertext = KF.chacha20(k.chachaKey, k.chachaNonce, pad(plaintext));
  const mac = KF.hmac(KF.sha256, k.hmacKey, concat(n, ciphertext));
  return b64encode(concat(new Uint8Array([2]), n, ciphertext, mac));
}

function nip44Decrypt(payload, convKey) {
  if (typeof payload !== "string" || payload.length < 132 || payload[0] === "#") {
    throw new Error("nip44: unreadable payload");
  }
  const bytes = b64decode(payload);
  if (bytes[0] !== 2) throw new Error("nip44: unknown version");
  const nonce = bytes.slice(1, 33);
  const ciphertext = bytes.slice(33, bytes.length - 32);
  const mac = bytes.slice(bytes.length - 32);
  const k = messageKeys(convKey, nonce);
  const expected = KF.hmac(KF.sha256, k.hmacKey, concat(nonce, ciphertext));
  // The MAC is what makes this authenticated rather than merely
  // scrambled, so it is checked before the plaintext is looked at.
  if (toHex(expected) !== toHex(mac)) throw new Error("nip44: bad mac");
  return unpad(KF.chacha20(k.chachaKey, k.chachaNonce, ciphertext));
}

/* ============================================================
   events, signed by a burner

   app.js signs with whatever holds this device's identity. Not
   one event in this file is signed by that key: a transfer is
   carried entirely by keys that exist for one session, which is
   what keeps a relay from learning who is pairing with whom.
   ============================================================ */
function serialize(ev) {
  return JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
}

async function eventId(ev) {
  return toHex(await S.utils.sha256(enc.encode(serialize(ev))));
}

async function signWith(privkey, partial) {
  const ev = {
    pubkey: toHex(S.schnorr.getPublicKey(privkey)),
    created_at: partial.created_at ?? nowSeconds(),
    kind: partial.kind,
    tags: partial.tags || [],
    content: partial.content || "",
  };
  ev.id = await eventId(ev);
  ev.sig = toHex(await S.schnorr.sign(ev.id, privkey));
  return ev;
}

function newBurner() {
  const priv = S.utils.randomPrivateKey();
  return { priv, pub: toHex(S.schnorr.getPublicKey(priv)) };
}

/* ---------- NIP-59: rumor, seal, wrap ---------- */

// The rumor is the message itself and is never signed: an unsigned
// event cannot be shown to anyone as proof that its author sent it,
// which is the property NIP-59 is after.
async function makeRumor(senderPub, kind, tags, content) {
  const rumor = {
    pubkey: senderPub,
    created_at: nowSeconds(),
    kind,
    tags,
    content: content || "",
  };
  rumor.id = await eventId(rumor);
  return rumor;
}

// §11.4: the true clock, contrary to NIP-59. The randomisation
// exists to hide when a message was written from somebody reading it
// later; here every wrap is published the instant it is made, both
// ends are burners that exist for one session, and it hides nothing
// while costing two things — a subscription that has to reach two
// days back to see anything, and a second timestamp to reason about
// beside the one the expiry is actually enforced against.
async function wrapRumor(rumor, senderPriv, recipientPubHex) {
  const seal = await signWith(senderPriv, {
    kind: KINDS.SEAL,
    tags: [],
    content: nip44Encrypt(JSON.stringify(rumor), conversationKey(senderPriv, recipientPubHex)),
  });
  const onetime = S.utils.randomPrivateKey();
  const wrap = await signWith(onetime, {
    kind: KINDS.GIFT_WRAP,
    tags: [
      ["p", recipientPubHex],
      // Advisory, and §11.4 says so: a relay may honour it, ignore
      // it, or serve the event long after it has lapsed. What
      // actually enforces the window is the rumor's own timestamp,
      // which is the one the seal signature covers.
      ["expiration", String(nowSeconds() + WRAP_EXPIRY_SECONDS)],
    ],
    content: nip44Encrypt(JSON.stringify(seal), conversationKey(onetime, recipientPubHex)),
  });
  wipe(onetime);
  return wrap;
}

// Returns the rumor and the key that sealed it, because the two have
// to be compared. §11.4: the rumor's own pubkey field is the sending
// burner and must equal the key that signed the seal. That is the
// whole of attribution — the sending burner appears in no other
// field — and a rumor failing it is somebody replaying somebody
// else's message under their own seal.
async function unwrap(wrapEvent, recipientPriv) {
  const sealJson = nip44Decrypt(wrapEvent.content, conversationKey(recipientPriv, wrapEvent.pubkey));
  const seal = JSON.parse(sealJson);
  if (seal.kind !== KINDS.SEAL) throw new Error("keyxfer: wrap did not hold a seal");
  if (!(await verifyEvent(seal))) throw new Error("keyxfer: seal signature does not check out");
  const rumorJson = nip44Decrypt(seal.content, conversationKey(recipientPriv, seal.pubkey));
  const rumor = JSON.parse(rumorJson);
  return { rumor, sealSigner: seal.pubkey };
}

async function verifyEvent(ev) {
  try {
    if (await eventId(ev) !== ev.id) return false;
    return await S.schnorr.verify(ev.sig, ev.id, ev.pubkey);
  } catch (err) {
    return false;
  }
}

// The `nostr-nsec` profile's P4 check. A scalar of zero or one at
// or above the curve order is not a key, and noble refuses to
// derive from it, so the derivation is the check.
function validPrivkeyHex(hex) {
  if (!/^[0-9a-f]{64}$/.test(hex)) return false;
  try {
    S.schnorr.getPublicKey(fromHex(hex));
    return true;
  } catch (err) {
    return false;
  }
}

function tagValue(tags, name) {
  for (const t of tags || []) if (t[0] === name) return t[1];
  return undefined;
}

/* ============================================================
   the short code (qrst §6)

   Five digits, derived from the profile, both burners and both
   random nonces. The device that made contact commits to its nonce
   before it learns the other's, which is what stops somebody in
   the middle from picking a nonce that makes two different codes
   match: they have to commit to a value before they can see what
   it must match, and each session gives them exactly one guess
   that either works or is a number the person is about to type
   somewhere it will be refused.

   Five, and not six or four, because no secret anybody holds is
   five digits long. A bank PIN is four and a message code is six,
   so a five-position field matches nothing a person could be
   phished into reaching for, and every honest transfer teaches
   that this is a number read off another screen rather than one
   already known.
   ============================================================ */
async function sasCommit(contactingPubHex, nonce) {
  return toHex(await S.utils.sha256(concat(
    enc.encode("qrst-commit"), new Uint8Array([VERSION_BYTE]),
    fromHex(contactingPubHex), nonce)));
}

// The order is the two roles — the party releasing the secret
// first, the party obtaining it second — and never the order the
// two messages happened to arrive in. The device that made contact
// is the releasing one in flow A and the obtaining one in flow B,
// so a version of this that hashed "me then them" would agree with
// itself and with nothing else. The vectors carry the transposed
// answer for exactly that reason.
//
// The version byte and then the profile, length-prefixed, so that
// two devices which disagree about which version they are speaking
// or what kind of secret is moving cannot arrive at the same
// number — the agreement about both is part of what the person
// checks rather than something checked afterwards.
async function sasCode(senderPubHex, receiverPubHex, nonceSender, nonceReceiver) {
  const profile = enc.encode(PROFILE);
  const code = await S.utils.sha256(concat(
    enc.encode("qrst-sas"), new Uint8Array([VERSION_BYTE]),
    new Uint8Array([profile.length]), profile,
    fromHex(senderPubHex), fromHex(receiverPubHex),
    nonceSender, nonceReceiver));
  // Five bytes rather than four, so that reducing them to five
  // digits leaves a bias too small to be worth a sentence.
  const n = code[0] * 4294967296 + (((code[1] << 24) | (code[2] << 16) |
    (code[3] << 8) | code[4]) >>> 0);
  const digits = String(n % 100000).padStart(5, "0");
  return { digits, hex: toHex(code) };
}

/* ============================================================
   the QR (qrst §11.2)

   An ordinary https link with every parameter in its fragment.
   There is no custom scheme: "qrst" names the mechanism, not a
   scheme, and may appear in the path.

   The fragment rather than the query, because a fragment is never
   sent to a server. The host the link names learns nothing from
   being asked for the page — not the burner key, not the relay
   list — and the ordinary path never asks it for anything at all,
   because a client whose own camera read the code takes the
   parameters straight out of the string.

   The host matters only for the one case where it has to: a
   platform camera app, which hands an https link to a browser and
   an unclaimed scheme to a web search. §11.2a is the page that
   answers on the other end of it.
   ============================================================ */

// Legal in a fragment and left alone, because a code somebody has to
// point a camera at pays for every character: escaping the colons and
// slashes in four relay URLs costs a whole QR version of density for
// nothing. Everything else is escaped, including the plus, which a
// parser reading the fragment back would otherwise take for a space.
function fragmentValue(text) {
  return encodeURIComponent(text).replace(/%3A/g, ":").replace(/%2F/g, "/");
}

// The base is the address the code sends a generic camera to, and is
// the caller's to choose: it is a property of where this copy is
// served from rather than of the transfer. The origin is the claim
// §9.1 makes the other device's consent prompt name, and is required
// of a web client and omitted by anything else.
function buildUri(params) {
  const npub = KF.bech32.encode("npub", KF.bech32.toWords(fromHex(params.burner)), 5000);
  const fields = [
    ["v", VERSION],
    ["mode", params.mode],
    // Required, and required even though hearth has exactly one:
    // it is hashed into the code the two devices compare, so a field
    // that is sometimes absent is two implementations disagreeing
    // about how to hash nothing.
    ["p", PROFILE],
    ["npub", npub],
  ];
  for (const relay of (params.relays || []).slice(0, 4)) fields.push(["relay", relay]);
  if (params.origin) fields.push(["origin", params.origin]);
  const fragment = fields.map(([k, v]) => k + "=" + fragmentValue(v)).join("&");
  return stripFragment(params.base) + "#" + fragment;
}

function stripFragment(base) {
  const at = String(base || "").indexOf("#");
  return at === -1 ? String(base || "") : String(base).slice(0, at);
}

/* The role the showing device holds, from what its code says. A
   `mode=offer` code is shown by the party obtaining the secret, so
   whoever scans it is releasing one; `mode=request` is the other way
   round. Named here because §11.2's role-collision rule is written
   about it and reads as nothing without it. */
function modeRole(mode) {
  return mode === "offer" ? "joiner" : "holder";
}

// Takes the whole link. `role` is the role this client has already
// committed to, where it has committed to one, so that a code from a
// device in the same position as this one is refused now and in
// words, rather than by a ceremony that completes and moves nothing.
function parseUri(text, opts) {
  let url;
  try {
    url = new URL(String(text || "").trim());
  } catch (err) {
    throw new Error("that code isn't a device code");
  }
  // http as well as https, because a copy served over plain http on a
  // local network is how this is worked on, and refusing it would
  // refuse the case where two devices are demonstrably in one room.
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("that code isn't a device code");
  }
  const q = new URLSearchParams(url.hash.slice(1));
  // A client must refuse a version it does not know, a code that
  // says nothing about which way the key is meant to travel, and a
  // code naming a kind of secret it cannot handle — the last one
  // before a burner exists, rather than at the end of a ceremony
  // somebody has already sat through.
  if (q.get("v") !== VERSION) throw new Error("that code comes from a newer version of hearth");
  const mode = q.get("mode");
  if (mode !== "offer" && mode !== "request") {
    throw new Error("that code doesn't say which device holds the key");
  }
  const profile = q.get("p");
  if (!profile) throw new Error("that code doesn't say what it's offering to move");
  if (profile !== PROFILE) {
    throw new Error("that code is moving something hearth doesn't handle (" + profile + ")");
  }
  // §11.2: a client that has already committed to a role refuses a
  // code that would give it the same one. Both devices would be
  // waiting to receive, or both offering, and neither would ever be
  // told why.
  if (opts && opts.role && modeRole(mode) === opts.role) {
    throw new Error("that code is from a device in the same position as this one, so " +
      "neither of you would be receiving anything");
  }
  const npub = q.get("npub");
  if (!npub) throw new Error("that code isn't a device code");
  let burner;
  try {
    const decoded = KF.bech32.decode(npub, 5000);
    if (decoded.prefix !== "npub") throw new Error("prefix");
    burner = toHex(Uint8Array.from(KF.bech32.fromWords(decoded.words)));
  } catch (err) {
    throw new Error("that code isn't a device code");
  }
  if (burner.length !== 64) throw new Error("that code isn't a device code");
  const relays = q.getAll("relay").slice(0, 4);
  return {
    burner,
    mode,
    profile,
    relays: relays.length > 0 ? relays : DEFAULT_RELAYS.slice(),
    origin: q.get("origin") || null,
  };
}

// Punycode where a host has non-ASCII in it, so that a domain
// built out of letters that look like other letters reads on the
// consent prompt as the address it actually is (§4).
function displayOrigin(origin) {
  if (!origin) return null;
  try {
    const url = new URL("https://" + origin);
    return url.hostname;
  } catch (err) {
    return origin;
  }
}

/* ============================================================
   relays

   One socket per relay, all of them subscribed to the same
   burner and all of them published to. A relay that refuses the
   publish is simply one that did not carry it; the others did.
   ============================================================ */
function relayPool(urls, burner, since, onEvent, onHealth) {
  const sockets = new Map();
  const seen = new Set();
  // §11.6: relays that have said they will not carry a message this
  // size. Dropped for the life of the session rather than retried,
  // because the answer will not change.
  const skipped = new Set();
  // Everything this session has published, kept so that a relay
  // whose socket opened late, or which asked for authentication
  // first, still receives the messages that went out before it was
  // ready. A session publishes a handful of small events, and a
  // relay seeing one twice discards the duplicate by id.
  const outbox = [];
  // One row per relay, for the whole life of the session: what it is
  // doing now, how many times it has been tried, how long it took to
  // open when it did, and what it said when it stopped. This is the
  // record to read when somebody reports that a transfer would not
  // start, because "no relay could be reached" on its own says
  // nothing about which one was slow or why.
  const health = new Map();
  const startedAt = Date.now();
  let closed = false;

  for (const url of urls.slice(0, 4)) {
    health.set(url, {
      status: "connecting", attempts: 0, openMs: null,
      subscribed: false, lastReason: null, retryInMs: null,
    });
  }

  function summary() {
    let live = 0;
    let usable = 0;
    for (const row of health.values()) {
      if (row.status === "open") live++;
      if (row.status !== "skipped") usable++;
    }
    return {
      live,
      // Every relay this session may still use. A relay skipped under
      // §11.6 is not one of them, and a screen counting it would say
      // it is still waiting on something that is never coming.
      usable,
      total: health.size,
      elapsedMs: Date.now() - startedAt,
      relays: Array.from(health, ([url, row]) => Object.assign({ url }, row)),
    };
  }

  function note(url, change) {
    const row = health.get(url);
    if (!row) return;
    Object.assign(row, change);
    // Logged as it happens rather than summarised at the end,
    // because the interesting case is the one where nothing ever
    // finishes and there is no end to summarise.
    console.info("hearth: transfer relay", url, row.status,
      row.openMs !== null ? row.openMs + "ms" : "",
      row.lastReason || "", "attempt " + row.attempts);
    if (onHealth) onHealth(summary());
  }

  function subscribe(ws) {
    ws.send(JSON.stringify(["REQ", "kx", {
      kinds: [KINDS.GIFT_WRAP],
      "#p": [burner.pub],
      // §11.5: the session's start, less the clock slack. It used to
      // reach two days back, which was the cost of a randomised wrap
      // timestamp; the wrap carries the true clock now, so the
      // window is the session and nothing more.
      since,
    }]));
  }

  function flush(ws) {
    for (const event of outbox) {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(["EVENT", event]));
    }
  }

  // A relay is tried again for as long as the session is alive. The
  // first attempt on a cold connection is the slow one — Safari
  // opening a first socket to a public relay can take longer than
  // anybody would guess — and the second is usually immediate, so
  // giving up on the first would be giving up on the case this most
  // needs to handle. Backoff so a relay that is genuinely down is
  // not hammered for ten minutes.
  function retry(url, reason) {
    if (closed || skipped.has(url)) return;
    const row = health.get(url);
    const delay = Math.min(8000, 1000 * Math.pow(2, Math.min(row.attempts - 1, 3)))
      + Math.floor(Math.random() * 400);
    note(url, { status: "waiting", lastReason: reason, retryInMs: delay, subscribed: false });
    setTimeout(() => connect(url), delay);
  }

  function connect(url) {
    if (closed || skipped.has(url)) return;
    const row = health.get(url);
    row.attempts++;
    const began = Date.now();
    let ws;
    let authId = null;
    // Fires once per socket: an error and a close both arrive for
    // one failure, and scheduling two retries would double the
    // attempts every round.
    let settled = false;

    try {
      ws = new WebSocket(url);
    } catch (err) {
      note(url, { status: "connecting", retryInMs: null });
      retry(url, err.message || "would not open");
      return;
    }
    sockets.set(url, ws);
    note(url, { status: "connecting", retryInMs: null, lastReason: null });

    ws.addEventListener("open", () => {
      if (closed) { try { ws.close(); } catch (e) {} return; }
      note(url, { status: "open", openMs: Date.now() - began, lastReason: null });
      subscribe(ws);
      flush(ws);
    });

    ws.addEventListener("message", async (evt) => {
      let frame;
      try { frame = JSON.parse(evt.data); } catch (e) { return; }
      if (frame[0] === "EVENT" && frame[1] === "kx") {
        const event = frame[2];
        // The same wrap arriving from three relays is one wrap.
        if (seen.has(event.id)) return;
        seen.add(event.id);
        onEvent(event);
        return;
      }
      if (frame[0] === "EOSE" && frame[1] === "kx") {
        note(url, { subscribed: true });
        return;
      }
      if (frame[0] === "CLOSED" && frame[1] === "kx") {
        // The socket is still up; it is the subscription that is
        // not, which is worth knowing apart from a dead connection.
        note(url, { subscribed: false, lastReason: "subscription refused: " + (frame[2] || "") });
        return;
      }
      if (frame[0] === "AUTH") {
        // Signed by the burner, never by this device's identity:
        // the wrap is addressed to the burner, which is what an
        // auth-gated relay wants to see, and it tells the relay
        // nothing it did not already know.
        const auth = await signWith(burner.priv, {
          kind: KINDS.CLIENT_AUTH,
          tags: [["relay", url], ["challenge", frame[1]]],
        });
        authId = auth.id;
        ws.send(JSON.stringify(["AUTH", auth]));
        return;
      }
      if (frame[0] === "OK" && frame[1] === authId && frame[2]) {
        // Authenticated now, so anything this relay refused before
        // it asked goes again, and the subscription it closed is
        // reopened.
        note(url, { lastReason: null });
        subscribe(ws);
        flush(ws);
        return;
      }
    });

    ws.addEventListener("close", (evt) => {
      if (sockets.get(url) === ws) sockets.delete(url);
      if (settled) return;
      settled = true;
      retry(url, "closed" + (evt && evt.code ? " (" + evt.code + ")" : ""));
    });

    ws.addEventListener("error", () => {
      if (settled) return;
      settled = true;
      retry(url, "connection failed");
    });
  }

  /* §11.6, run beside the connecting rather than in front of it. The
     screen is up either way — §11.3 is emphatic that a probe does not
     get to close out a session — so this is a relay being dropped
     when its answer arrives, not a gate anything waits behind. */
  function checkSize(url) {
    relayLimits(url).then((limits) => {
      if (closed) return;
      const why = tooSmall(limits);
      if (!why) return;
      skipped.add(url);
      const ws = sockets.get(url);
      if (ws) { try { ws.close(); } catch (e) {} sockets.delete(url); }
      note(url, { status: "skipped", lastReason: why, subscribed: false, retryInMs: null });
    }).catch(() => {
      // A document that would not load says nothing about what the
      // relay carries. §11.6 skips a stated ceiling, and silence is
      // not one.
    });
  }

  for (const url of health.keys()) { connect(url); checkSize(url); }

  return {
    publish(event) {
      outbox.push(event);
      const frame = JSON.stringify(["EVENT", event]);
      let sent = 0;
      for (const ws of sockets.values()) {
        if (ws.readyState === WebSocket.OPEN) { ws.send(frame); sent++; }
      }
      // Nought here is a socket that has not finished opening
      // rather than a failure: the flush above sends it the moment
      // one does, and a relay still being retried will get it when
      // it comes up.
      return sent;
    },
    summary,
    close() {
      closed = true;
      for (const ws of sockets.values()) { try { ws.close(); } catch (e) {} }
      sockets.clear();
    },
  };
}

/* the probe (qrst §11.3, §11.6)

   §11.3 asks for a probe before the transfer screen goes up, and
   then says what it is for: it is advisory, not selective. A
   three-second probe must not close out a ten-minute session, so the
   screen goes up regardless, an unreachable relay is re-attempted
   for the whole of the session's remaining life, the flow proceeds
   the moment one becomes reachable, and failure is reported only at
   expiry. That is what the pool above does — it starts connecting
   when the session does and keeps at it — and how it is getting on
   is something the screen reports rather than something the session
   rules on.

   The part of the probe that does decide something is §11.6. A relay
   that says in its NIP-11 document that it cannot carry the profile's
   maximum message is skipped, because it will accept the handshake
   and then drop the one message that matters. A relay that declares
   no limit is kept: the rule is for a stated ceiling, and an absent
   one is not a small one.

   For this profile the check will essentially never bind. The
   payload is sixty-four characters and the ceiling is two kilobytes,
   three orders of magnitude apart, and the default was chosen to be
   the figure every operator observed already carries. It is here
   because a client that skips it passes on a profile with a larger
   maximum, and because a relay that declares a small limit is worth
   naming on the screen rather than leaving as a socket that opens
   and then silently swallows the key. */

// §4 P1: the default maximum, which `nostr-nsec` takes as its own.
const MAX_PAYLOAD_BYTES = 2048;
// §11.6's own arithmetic: a `max_content_length` of 8196 carries a
// 2082-byte payload, so the content field costs a little under four
// bytes for every byte of payload. Derived from the table rather than
// from the ×3.4 figure beside it, because that one measures the whole
// published event and this limit caps the content field alone.
const REQUIRED_CONTENT_LENGTH = Math.ceil(MAX_PAYLOAD_BYTES * 8196 / 2082);
// The same, plus what the event around it and the relay frame cost:
// an id, a signature, a pubkey, the tags and the JSON holding them.
// Five hundred bytes covers it and this is four times that, because
// being generous here skips fewer relays and the figure it is
// protecting against is an order of magnitude below either.
const REQUIRED_MESSAGE_LENGTH = REQUIRED_CONTENT_LENGTH + 2048;

// NIP-11 is served over http from the relay's own address.
function nip11Url(relayUrl) {
  return relayUrl.replace(/^ws:/, "http:").replace(/^wss:/, "https:");
}

// What the relay says it will carry, or nothing. Nothing is the
// ordinary answer — a document that will not load, a relay that
// serves no CORS header, a field it does not declare — and it is
// deliberately not a reason to skip anything.
async function relayLimits(relayUrl) {
  if (typeof global.fetch !== "function") return null;
  const response = await global.fetch(nip11Url(relayUrl), {
    headers: { Accept: "application/nostr+json" },
  });
  if (!response.ok) return null;
  return await response.json();
}

// A stated ceiling this profile does not fit under, in words a
// screen can show, or null for a relay that is fine or silent.
function tooSmall(limits) {
  if (!limits || typeof limits !== "object") return null;
  const content = Number(limits.max_content_length);
  if (Number.isFinite(content) && content > 0 && content < REQUIRED_CONTENT_LENGTH) {
    return "carries messages of at most " + content + " bytes";
  }
  const message = Number(limits.max_message_length);
  if (Number.isFinite(message) && message > 0 && message < REQUIRED_MESSAGE_LENGTH) {
    return "carries messages of at most " + message + " bytes";
  }
  return null;
}

/* ============================================================
   what a failed code costs (qrst §9)

   Attempts inside one session buy an attacker nothing: their value
   was fixed when the nonces were revealed, so retyping can only
   fail against the same number. Every chance they get comes from a
   *new* session, which is why the expensive thing is starting one
   again rather than typing again.

   Two records, both kept for an hour. The burners this device has
   failed a code against, so that rescanning a screen still showing
   the same QR cannot quietly reuse the same peer — the far side has
   no way to know a code was failed, so refusing has to happen here.
   And how many sessions have failed, so that a third one in an hour
   can say that this pattern is what interference looks like, rather
   than leaving somebody to conclude they keep mistyping.

   In localStorage because an hour outlasts a reload. A device with
   no storage keeps them for the life of the page, which is weaker
   than the specification asks and better than dropping the rule.
   ============================================================ */
const FAILED_BURNERS_KEY = "qrst:failed-burners";
const FAILED_SESSIONS_KEY = "qrst:failed-sessions";
const memoryFallback = new Map();

function readRecord(key) {
  let raw = memoryFallback.get(key);
  try {
    if (global.localStorage) raw = global.localStorage.getItem(key);
  } catch (err) {
    // Storage disabled or partitioned away. The fallback above is
    // what this device gets.
  }
  let parsed;
  try { parsed = JSON.parse(raw || "[]"); } catch (err) { parsed = []; }
  if (!Array.isArray(parsed)) parsed = [];
  const cutoff = Date.now() - FAILURE_MEMORY_MS;
  return parsed.filter((row) => row && typeof row.at === "number" && row.at > cutoff);
}

function writeRecord(key, rows) {
  const raw = JSON.stringify(rows.slice(-64));
  memoryFallback.set(key, raw);
  try {
    if (global.localStorage) global.localStorage.setItem(key, raw);
  } catch (err) {
    // As above.
  }
}

// Whether this device has already failed a code against that
// burner, and so must not start a second session with it.
function burnerRefused(pubHex) {
  return readRecord(FAILED_BURNERS_KEY).some((row) => row.burner === pubHex);
}

function rememberFailure(pubHex) {
  const burners = readRecord(FAILED_BURNERS_KEY);
  burners.push({ burner: pubHex, at: Date.now() });
  writeRecord(FAILED_BURNERS_KEY, burners);
  const sessions = readRecord(FAILED_SESSIONS_KEY);
  sessions.push({ at: Date.now() });
  writeRecord(FAILED_SESSIONS_KEY, sessions);
  return sessions.length;
}

// Three in an hour is the point at which the person is told that
// this is what somebody interfering looks like.
function failuresWorthMentioning() {
  return readRecord(FAILED_SESSIONS_KEY).length >= FAILED_SESSIONS_BEFORE_WARNING;
}

/* ============================================================
   a session

   One transfer attempt, ten minutes, one burner. The caller hands
   in what it is (holder or joiner, showing the code or scanning
   one) and a place to send screen updates, and drives it with
   four decisions: approve, deny, choose, accept.
   ============================================================ */
function startSession(opts) {
  const role = opts.role;                   // "holder" | "joiner"
  const showing = !!opts.showing;           // does this device draw the QR
  // Flow A is the joiner showing (§7); flow B is the holder
  // showing (§8). Which one this is decides who commits first,
  // and getting that backwards makes two honest devices show
  // different codes.
  const flow = (role === "joiner") === showing ? "A" : "B";
  const contacting = !showing;              // the device that scanned made contact
  const emit = opts.on || function () {};

  const burner = newBurner();
  const startedAt = nowSeconds();
  const peers = new Map();                  // their burner hex -> peer state
  let ownNonce = null;
  let ownCommit = null;
  let awaitingConsent = null;
  let everLive = false;
  let pool = null;
  let finished = false;
  let multiSeen = false;
  // §9: five code entries, counted across the session rather than
  // per peer, because the budget exists to cover a person working
  // through the two or three codes a second scanner put on the far
  // screen as well as their own mistypes.
  let attemptsLeft = MAX_ATTEMPTS;
  // §9.2: which candidate's code is on screen, and which candidate is
  // being asked about. One at a time in both cases, first responder
  // first, and it is never all of them at once.
  let displayAt = 0;
  let scanned = opts.scanned || null;       // what the QR said, when we scanned one
  const relays = (scanned ? scanned.relays : (opts.relays || DEFAULT_RELAYS)).slice(0, 4);

  const sessionTimer = setTimeout(() => stop("expired"), SESSION_SECONDS * 1000);
  let zeroizeTimer = null;

  function peerFor(pubHex) {
    let peer = peers.get(pubHex);
    if (!peer) {
      peer = { burner: pubHex, nonce: null, theirNonce: null, commit: null, sas: null, held: null };
      peers.set(pubHex, peer);
    }
    return peer;
  }

  // §13. Counted on the device that showed the code, because that
  // is the code somebody else may have pointed a camera at. The
  // session carries on: the code on the two screens is what
  // settles which of them is real, and this is a notice rather
  // than a refusal.
  function noteResponder() {
    if (!showing || multiSeen || peers.size < 2) return;
    multiSeen = true;
    emit("multi");
  }

  // Nothing here treats "no socket was open at this instant" as a
  // failure. The pool keeps what it was given and sends it to each
  // relay as that relay finishes connecting, which is the ordinary
  // case for the first message of a session: it is composed the
  // moment the QR is scanned, and the sockets are still opening.
  async function send(kind, tags, content, toPubHex) {
    // No version tag: §11.4 says messages carry none. The session's
    // version is fixed by the QR and hashed into the commit and the
    // code, so a peer speaking a different one cannot agree on a
    // number with this device and never gets as far as a message.
    const rumor = await makeRumor(burner.pub, kind, tags, content);
    const wrap = await wrapRumor(rumor, burner.priv, toPubHex);
    return pool ? pool.publish(wrap) : 0;
  }

  // §9's ABORT. A courtesy and nothing more: its absence means
  // nothing and the far side must not depend on it. It is still
  // worth actually sending, which takes a moment — sealing and
  // wrapping are asynchronous — so a caller that is about to end
  // the session has to wait for this rather than closing the
  // sockets out from under it.
  function abortTo(peerHex) {
    return send(KINDS.ABORT, [], "", peerHex).catch(() => 0);
  }

  // The same, for the callers that end the session immediately
  // afterwards. Bounded, because a message nobody is required to
  // receive must not be able to hold up the screen.
  function abortThen(peerHex, after) {
    let done = false;
    const go = () => { if (!done) { done = true; after(); } };
    abortTo(peerHex).then(() => setTimeout(go, 200), go);
    setTimeout(go, 1500);
  }

  // Everything a rumor has to satisfy before it is looked at as a
  // message rather than as bytes somebody sent.
  function admissible(rumor, sealSigner) {
    // §11.4's attribution check, and the whole of it: the rumor's own
    // pubkey is the sending burner and must be the key that signed
    // the seal, or somebody is forwarding a message that was not
    // theirs. Hearth used to require a `burner` tag saying the same
    // thing a third time. Reserved tag names are `commit` and
    // `nonce`; no other client sends a third, so requiring one meant
    // discarding every message any of them ever sent.
    if (rumor.pubkey !== sealSigner) return false;
    // §11.4: a rumor whose own created_at is outside this session is
    // discarded from the session entirely — here and not anywhere
    // later, so that a backdated timestamp cannot buy its sender a
    // quiet arrival that skips the notice above, and so that it is
    // never a candidate rather than merely uncounted.
    const at = rumor.created_at;
    if (typeof at !== "number") return false;
    if (at < startedAt - CLOCK_SLACK) return false;
    if (at > startedAt + SESSION_SECONDS + CLOCK_SLACK) return false;
    return true;
  }

  async function onWrap(wrapEvent) {
    if (finished) return;
    let opened;
    try {
      opened = await unwrap(wrapEvent, burner.priv);
    } catch (err) {
      // A wrap that will not open is not a responder (§13). It is
      // most likely addressed to somebody else on a relay that
      // does not filter as tightly as it claims.
      return;
    }
    const { rumor, sealSigner } = opened;
    if (!admissible(rumor, sealSigner)) return;
    // When this device scanned a QR it is talking to exactly one
    // burner, the one the QR named, and anything else is noise.
    if (scanned && sealSigner !== scanned.burner) return;
    try {
      await handleRumor(rumor, sealSigner);
    } catch (err) {
      emit("error", err.message);
    }
  }

  async function handleRumor(rumor, from) {
    /* ---- the contacting device's opening message ---- */
    if (rumor.kind === KINDS.HELLO || rumor.kind === KINDS.REQUEST) {
      const expected = flow === "A" ? KINDS.HELLO : KINDS.REQUEST;
      if (rumor.kind !== expected || contacting) return;
      const existing = peers.get(from);
      // A retransmission from a burner already answered is the
      // same responder, not a second one (§13).
      if (existing && existing.commit) return;
      // §13: three held, so a flooder costs the person a couple of
      // taps rather than an unbounded queue. A later responder is
      // dropped, never a reason to abort — seeing a code is not
      // evidence of an attack, and a session that aborted on one
      // could be denied by anybody who photographed the code.
      if (peers.size >= HELD_MAX) { noteResponder(); return; }
      const commit = tagValue(rumor.tags, "commit");
      if (!commit) return;
      const peer = peerFor(from);
      peer.commit = commit;
      peer.nonce = S.utils.randomBytes(32);
      noteResponder();
      await send(KINDS.NONCE, [["nonce", toHex(peer.nonce)]], "", from);
      return;
    }

    /* ---- the other device's nonce, answering our commit ---- */
    if (rumor.kind === KINDS.NONCE) {
      if (!contacting) return;
      const peer = peerFor(from);
      if (peer.theirNonce) return;
      const nonce = tagValue(rumor.tags, "nonce");
      if (!nonce || nonce.length !== 64) return;
      peer.theirNonce = fromHex(nonce);
      await send(KINDS.REVEAL, [["nonce", toHex(ownNonce)]], "", from);
      await settleSas(peer);
      return;
    }

    /* ---- the contacting device opening its commit ---- */
    if (rumor.kind === KINDS.REVEAL) {
      if (contacting) return;
      const peer = peers.get(from);
      if (!peer || !peer.commit || peer.theirNonce) return;
      const nonce = tagValue(rumor.tags, "nonce");
      if (!nonce || nonce.length !== 64) return;
      // The whole point of the commitment: the nonce revealed now
      // has to be the nonce promised before ours was sent.
      const check = await sasCommit(from, fromHex(nonce));
      if (check !== peer.commit) return;
      peer.theirNonce = fromHex(nonce);
      await settleSas(peer);
      return;
    }

    /* ---- the key itself ---- */
    if (rumor.kind === KINDS.PAYLOAD) {
      if (role !== "joiner") return;
      const peer = peers.get(from);
      // Only from a burner this device is already exchanging
      // nonces with. A key from a burner that never did is one
      // nobody asked for.
      if (!peer || !peer.nonce && !peer.theirNonce) return;
      const hex = (rumor.content || "").trim().toLowerCase();
      // The profile's P4 check: sixty-four hex characters that are
      // a scalar in range and give a usable public key. Anything
      // else is not a key and is not held as though it might be.
      if (!validPrivkeyHex(hex)) return;
      // Held, not stored. Nothing is written until the person has
      // picked the code their other device is showing and agreed
      // to the identity that came with it: without that, whoever
      // photographed the QR could race the real holder and put
      // their own key on this device.
      // The tags come up with it. §5 item 6: a profile may put its own
      // on any message, and this file has no idea what they mean —
      // `lock` is pulled out because the profile the specification
      // registers defines it, and the rest are handed on whole.
      peer.held = { hex, lock: tagValue(rumor.tags, "lock") || "device", tags: rumor.tags || [] };
      maybeArrived(peer);
      return;
    }

    /* ---- the other side giving up (§9) ---- */
    // Sent by a holder whose person could not enter this device's
    // code. Nothing is proved by it and nothing depends on it — a
    // session that never receives one times out as usual — but a
    // joiner that does receive one can stop showing a code nobody
    // is going to type and put a fresh one up instead.
    if (rumor.kind === KINDS.ABORT) {
      const peer = peers.get(from);
      if (!peer) return;
      peers.delete(from);
      if (awaitingConsent === from) awaitingConsent = null;
      emit("peer-gone", { peer: from });
      return;
    }

    /* ---- the receipt that lets a holder let go ---- */
    if (rumor.kind === KINDS.ACK) {
      if (role !== "holder") return;
      const peer = peers.get(from);
      if (!peer || !peer.sent) return;
      stop("done");
      return;
    }

    /* ---- anything else ---- */
    // Dropped, and there used to be a way to hand it up. P2: one
    // payload, one session, and a session carries exactly one message
    // with meaning to the profile. §11.4 says the same from the other
    // end — there is no side-channel for additional profile messages.
    // A client with something to send alongside the key sends it as a
    // tag on the payload, which is what §5 item 6 is for.
  }

  // Both nonces are in, so both devices can work out the same five
  // figures. What happens next is the only thing the two roles do
  // differently at this point: a holder is asked to release the
  // key, a joiner is told what to show.
  async function settleSas(peer) {
    // Role order, holder first, whichever of the two this device
    // happens to be and whichever message arrived first. Our own
    // nonce is the one we committed to if we made contact, and the
    // one generated for this peer if we did not.
    const mine = contacting ? ownNonce : peer.nonce;
    const theirs = peer.theirNonce;
    const holderPub = role === "holder" ? burner.pub : peer.burner;
    const joinerPub = role === "joiner" ? burner.pub : peer.burner;
    const nonceHolder = role === "holder" ? mine : theirs;
    const nonceJoiner = role === "joiner" ? mine : theirs;
    peer.sas = await sasCode(holderPub, joinerPub, nonceHolder, nonceJoiner);
    if (role === "holder") {
      askConsent(peer);
    } else {
      // §9.2: one candidate's code, the active one. A second device
      // answering does not take the screen from the first.
      emit("sas", activeView());
      maybeArrived(peer);
    }
  }

  // §13: one at a time. A second device asking while the person is
  // reading the first prompt waits its turn rather than replacing
  // what is on screen under their thumb.
  function askConsent(peer) {
    if (awaitingConsent && peers.has(awaitingConsent)) return;
    const at = candidates().findIndex((p) => p.burner === peer.burner);
    displayAt = at < 0 ? 0 : at;
    showConsent(peer);
  }

  /* §9.2: the value the person obtained matched nothing this device
     is holding for the candidate it is asking about, so the question
     moves to the next one. This is not a second guess at the same
     code — each candidate's code was fixed when its nonces were
     revealed and nobody in the middle can influence it — which is
     why the specification says the budget disambiguates candidates
     rather than granting attempts. */
  function advanceConsent() {
    const list = candidates();
    if (list.length <= 1) return false;
    for (let step = 1; step <= list.length; step++) {
      const at = (displayAt + step) % list.length;
      if (list[at].sent) continue;
      displayAt = at;
      showConsent(list[at]);
      return true;
    }
    return false;
  }

  function showConsent(peer) {
    awaitingConsent = peer.burner;
    emit("consent", {
      peer: peer.burner,
      sas: peer.sas,
      // §9.1: the origin the other device claims, or nothing. There
      // is no third answer. A peer that states no origin has not
      // thereby said it is native — its nature is simply unestablished
      // — and the friction tier fails closed on that, which is the
      // caller's rule to apply rather than this file's to soften.
      origin: scanned ? displayOrigin(scanned.origin) : null,
      // Whether this session's pairing was read by this device's own
      // camera is something only the caller knows: a fragment on a
      // page load looks the same whichever app put it there.
      position: (displayAt % Math.max(1, candidates().length)) + 1,
      total: candidates().length,
    });
  }

  // A wrap carrying the key and the code that says whose it is can
  // arrive in either order, since they travel as separate events
  // over as many as four relays. The screen is told only once both
  // are in hand.
  function maybeArrived(peer) {
    if (!peer || !peer.held || !peer.sas || peer.announced) return;
    // §9.4: the candidate to commit is the one whose code the sender
    // confirmed, and that is the one whose code was on this screen
    // when they read it. A key from any other candidate is held out
    // of sight until the display reaches it, so nothing arrives
    // under somebody who is looking at a different number.
    const showing = active();
    if (!showing || showing.burner !== peer.burner) return;
    peer.announced = true;
    emit("arrived", { peer: peer.burner, sas: peer.sas });
  }

  /* §13: the candidates, first responder first. Arrival order and
     not the reverse of it, because the specification names the first
     responder as the active one and a list starting at the newest
     puts the device that answered a code somebody else pointed a
     camera at in front of the one that answered honestly. A Map
     keeps its insertion order, so this is the order they arrived in.

     A denied candidate is out of the list. A spent one is not: it is
     still a device that answered, and dropping it would renumber the
     positions the person is being shown. */
  function candidates() {
    const out = [];
    for (const peer of peers.values()) if (peer.sas && !peer.denied) out.push(peer);
    return out.slice(0, HELD_MAX);
  }

  // The one whose code is on screen, or which is being asked about.
  // The cursor wraps, because with three at the outside a person who
  // has gone past their own device should not be stuck past it.
  function active() {
    const list = candidates();
    if (list.length === 0) return null;
    return list[displayAt % list.length];
  }

  function activeView() {
    const peer = active();
    if (!peer) return null;
    const list = candidates();
    return {
      peer: peer.burner,
      sas: peer.sas,
      position: (displayAt % list.length) + 1,
      total: list.length,
      held: !!peer.held,
    };
  }

  function stop(reason, detail) {
    if (finished) return;
    finished = true;
    clearTimeout(sessionTimer);
    clearTimeout(zeroizeTimer);
    if (pool) pool.close();
    for (const peer of peers.values()) {
      if (peer.held) peer.held.hex = "";
      wipe(peer.nonce);
    }
    wipe(burner.priv);
    wipe(ownNonce);
    emit(reason, detail);
  }

  /* ---- what the screen can ask of a session ---- */
  const session = {
    flow,
    role,
    burner: burner.pub,
    uri: null,

    // Holder, both flows: the five digits the other device is
    // showing, typed here by the person holding both. §9 — the
    // code is never sent anywhere, never compared by the far side,
    // and never accepted on the far side's say-so. It is checked
    // against the number this device worked out for itself, which
    // is the one thing an attacker in the middle cannot influence.
    //
    // Returns what the screen should say, and nothing else
    // happens: a matching code makes the key releasable, it does
    // not release it. The tap that does is `approve` below.
    submitCode(peerHex, typed) {
      const peer = peers.get(peerHex);
      if (!peer || !peer.sas || finished) return { ok: false, reason: "gone" };
      if (attemptsLeft <= 0) return { ok: false, reason: "spent", left: 0 };
      // Exactly five digits. A field that quietly accepts more is a
      // field that cannot tell somebody the length is the point.
      const value = String(typed || "").trim();
      if (!/^[0-9]{5}$/.test(value)) return { ok: false, reason: "shape", left: attemptsLeft };
      if (value === peer.sas.digits) {
        peer.verified = true;
        return { ok: true };
      }
      attemptsLeft--;
      if (attemptsLeft > 0) {
        // §9.2: no match here means the next held candidate, where
        // there is one. The prompt for it goes up as this returns.
        const advanced = advanceConsent();
        return { ok: false, reason: "mismatch", left: attemptsLeft, advanced };
      }
      // Spent. §9: the session is dead, the burner goes, and this
      // peer is refused a second session for an hour, because the
      // far side is still showing the same QR and has no way to
      // know a code was ever failed. Refusing has to happen here or
      // rescanning that screen quietly reuses the same burner.
      const failures = rememberFailure(peerHex);
      const worthMentioning = failuresWorthMentioning();
      // The session is over from this moment — the guard above
      // refuses anything further — but the sockets stay up just
      // long enough for the far side to be told, so it can stop
      // showing a code nobody is going to type.
      abortThen(peerHex, () => stop("failed", { failures, worthMentioning }));
      return { ok: false, reason: "spent", left: 0 };
    },

    // Holder, both flows: release the key to this peer. Reached
    // only after the code was entered and matched, and then only
    // from a deliberate tap on the device that holds it.
    async approve(peerHex, privkeyHex, opts) {
      const peer = peers.get(peerHex);
      if (!peer || !peer.sas || finished) return;
      // The gate, and it is here rather than on the screen so that
      // no arrangement of buttons can get past it.
      if (!peer.verified) return;
      peer.sent = true;
      // §5 item 6: the caller's own tags ride the payload, because
      // P2 leaves nowhere else for them. They must not collide with
      // `commit` or `nonce`, which are the specification's; this file
      // does not police that, since a profile is what says which tags
      // it defines and the reserved names are not among them.
      const extra = (opts && opts.tags) || [];
      const lock = (opts && opts.lock) || "device";
      await send(KINDS.PAYLOAD, [["lock", lock]].concat(extra), privkeyHex, peerHex);
      emit("sent", { peer: peerHex, sas: peer.sas });
      // §7 step 18 and §8 step 18: the burner goes when the other
      // device says it has the key, or a minute later regardless.
      // A joiner that never acknowledges is one that never
      // stored it, and holding a burner open past that is holding
      // a channel open for nobody.
      zeroizeTimer = setTimeout(() => stop("done"), ZEROIZE_AFTER_MS);
    },

    // Holder, both flows: this request is not mine.
    deny(peerHex) {
      const peer = peers.get(peerHex);
      if (peer) { peer.denied = true; peers.delete(peerHex); }
      if (awaitingConsent === peerHex) awaitingConsent = null;
      // §8 step 13: in flow B this device is showing a code that
      // anybody may still scan, so a denial moves on to whoever
      // else is queued, or back to waiting. The person being added
      // may well be the next one along.
      //
      // §7 step 13 is the opposite and says so: in flow A this
      // device scanned one code and is talking to exactly one
      // burner, so declining it leaves nobody to wait for. Saying
      // "waiting for your other device" there is waiting for
      // something that cannot arrive.
      if (flow === "A") {
        abortThen(peerHex, () => stop("declined"));
        return;
      }
      // So the far side can stop showing a code and say what
      // happened, rather than waiting out ten minutes for somebody
      // who has already said no.
      abortTo(peerHex);
      awaitingConsent = null;
      displayAt = 0;
      const next = candidates().find((p) => !p.sent);
      if (next) askConsent(next);
      else emit("waiting");
    },

    // Joiner, flow A: the code this device is showing matched the
    // one on the other screen, so this is the wrap to open.
    chosen(peerHex) {
      const peer = peers.get(peerHex);
      if (!peer || !peer.held) return null;
      return { pubkey: toHex(S.schnorr.getPublicKey(fromHex(peer.held.hex))), peer: peerHex };
    },

    // Joiner: the identity is the right one, so keep it. Every
    // other pending wrap is dropped unopened.
    async accept(peerHex) {
      const peer = peers.get(peerHex);
      if (!peer || !peer.held || finished) return null;
      const held = peer.held;
      // §13: the profile's check again, at acceptance. It was made
      // when the key arrived and nothing has touched it since, so
      // this should never fire — but the section says a candidate
      // failing it here is discarded and the display moves on, and a
      // rule that only holds because of where an earlier check
      // happens to sit is one line away from not holding.
      if (!validPrivkeyHex(held.hex)) {
        peer.held = null;
        peer.announced = false;
        peers.delete(peerHex);
        const next = candidates().find((p) => p.held);
        if (next) { displayAt = candidates().indexOf(next); maybeArrived(next); }
        else stop("declined");
        return null;
      }
      const record = {
        privkeyHex: held.hex,
        lock: held.lock,
        // Whatever else the profile put on the payload. Opaque here.
        tags: held.tags,
        sas: peer.sas,
        peer: peerHex,
        multi: multiSeen,
      };
      await send(KINDS.ACK, [], "", peerHex);
      // A moment for the acknowledgement to reach a relay before
      // the sockets are closed under it; the holder's own minute
      // covers it either way.
      setTimeout(() => stop("done"), 400);
      return record;
    },

    cancel() { stop("cancelled"); },
    peers() {
      return candidates().map((peer) => ({ peer: peer.burner, sas: peer.sas }));
    },

    // §9.2, the receiving side: the code on screen now, and how far
    // through the held candidates it is.
    showing() { return activeView(); },

    // §9.2: the value the sender obtained matched none of what this
    // device is showing, so the display moves to the next candidate.
    // Driven from here rather than from a message, because the far
    // side has no way to tell this one that a code did not match.
    nextCode() {
      const list = candidates();
      if (list.length === 0) return null;
      displayAt = (displayAt + 1) % list.length;
      const view = activeView();
      // A candidate whose key is already in hand: the person has
      // arrived at the device that really did send one.
      if (view && view.held) maybeArrived(active());
      return view;
    },

    // The keys in hand, first responder first. One is the ordinary
    // case; more than one means two devices both got a code typed at
    // them, which takes somebody entering two codes on purpose. Only
    // the one whose code is on screen is ever offered (§9.4).
    held() {
      const out = [];
      for (const peer of peers.values()) {
        if (peer.held && peer.sas) out.push({ peer: peer.burner, sas: peer.sas });
      }
      return out;
    },

    // How each relay is getting on, for a screen that wants to say
    // so and for anybody reading a report of a transfer that would
    // not start.
    transport() { return pool ? pool.summary() : null; },
  };

  // Getting started: a burner, a subscription, and either a QR to
  // draw or a first message to send.
  (async function begin() {
    pool = relayPool(relays, burner, startedAt - CLOCK_SLACK, onWrap, (health) => {
      if (health.live > 0 && !everLive) {
        everLive = true;
        emit("connected", health);
      }
      emit("transport", health);
    });

    if (showing) {
      session.uri = buildUri({
        burner: burner.pub,
        mode: role === "joiner" ? "offer" : "request",
        relays,
        // Where the code sends a camera that is not a client of this
        // specification: this copy of whatever is running it, by
        // default, which is the only address it can know is serving
        // the page it is part of.
        base: opts.base || (global.location
          ? global.location.origin + global.location.pathname : ""),
        // Required of a web client and omitted by anything else
        // (§11.2). A caller that is not a browser passes null.
        origin: opts.origin !== undefined
          ? opts.origin
          : (global.location ? global.location.host : null),
      });
      emit("qr", session.uri);
      return;
    }

    // §9: a burner this device has already failed a code against
    // does not get a second session. The far side is still showing
    // the same QR — it cannot know a code was failed — so a person
    // who rescans that screen would otherwise hand the same peer
    // another attempt, which is the one thing the attempt budget
    // exists to prevent.
    if (role === "holder" && burnerRefused(scanned.burner)) {
      stop("refused", { worthMentioning: failuresWorthMentioning() });
      return;
    }

    // The scanning device is the one that made contact, so it is
    // the one that commits to a nonce before it can see the
    // other's.
    ownNonce = S.utils.randomBytes(32);
    ownCommit = await sasCommit(burner.pub, ownNonce);
    const kind = flow === "A" ? KINDS.HELLO : KINDS.REQUEST;
    // The profile's REQUEST also carries an `enroll` tag naming a
    // threshold enrolment key. Hearth has no threshold signing and
    // so has no such key, and a tag naming a key that does not
    // exist would be worse than an absent one.
    peerFor(scanned.burner);
    await send(kind, [["commit", ownCommit]], "", scanned.burner);
    emit("sent-hello");
  })();

  return session;
}

global.Keyxfer = {
  PROFILE,
  DEFAULT_RELAYS,
  KINDS,
  SESSION_SECONDS,
  MAX_ATTEMPTS,
  burnerRefused,
  failuresWorthMentioning,
  // The pieces below are exported for the vector checker, which
  // has to be able to reach every step the specification pins a
  // known answer to.
  nip44Encrypt,
  nip44Decrypt,
  conversationKey,
  paddedLength,
  sasCommit,
  sasCode,
  wrapRumor,
  unwrap,
  makeRumor,
  signWith,
  buildUri,
  parseUri,
  modeRole,
  displayOrigin,
  startSession,
  toHex,
  fromHex,
};

})(typeof window !== "undefined" ? window : globalThis);
