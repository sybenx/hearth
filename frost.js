/* ============================================================
   splitting a key, and signing with the pieces

   This is NOSTR_KEY_MANAGEMENT.md §7's arithmetic and nothing else.
   It knows what a share is, what an index means and how two of them
   make a signature; it does not know what a device is, where an
   epoch record goes, or that hearth exists. The screens, the device
   list and the events belong in app.js, as kinds.js explains.

   One async door in front of all of it. Everything here returns a
   promise, and the first call is what loads the implementation —
   about seventy kilobytes that a person who never splits their key
   never downloads. That is worth the awkwardness of an async
   interface in front of arithmetic that is not: the base app is a
   chat client, and paying for threshold signing to open a
   conversation would be paying for something almost nobody turns on.

   The same door is what makes the implementation replaceable. It is
   @noble/curves' `schnorr_FROST` today, which is RFC 9591 over the
   secp256k1 Taproot ciphersuite §7.4 names; the alternative was
   compiling the Rust crate that section names to WebAssembly.
   Whichever is behind it, callers see the vocabulary below.

   Two things this file does not decide, deliberately. It does not
   say how many messages a signature takes: `round1` and `round2` are
   the two rounds RFC 9591 defines, and whether they cost one round
   trip or two is the messaging layer's to arrange. And it does not
   negate anything for parity. §7.4 tells the dealer to use
   `a_0 = n − nsec` for an odd-y key and in the same breath names a
   ciphersuite that handles BIP-340 parity itself; doing both deals
   from a pre-negated secret and then negates again, and the group
   key is no longer the person's npub. Dealing from the raw key is
   what the specification's own vectors do, and `split` checks the
   result against the npub before returning it, so the question
   cannot be got wrong quietly.
   ============================================================ */
(function (global) {
"use strict";

const BUNDLE = "vendor/noble-frost.js";

let loading = null;

// Loaded once, on the first operation. A second call while the first
// is in flight waits on the same promise rather than adding a second
// script tag.
function load() {
  if (global.NobleFrost) return Promise.resolve(global.NobleFrost);
  if (loading) return loading;
  loading = new Promise((resolve, reject) => {
    const el = document.createElement("script");
    el.src = BUNDLE;
    el.async = true;
    el.addEventListener("load", () => {
      if (global.NobleFrost) resolve(global.NobleFrost);
      else reject(new Error("the threshold signing code loaded but defined nothing"));
    });
    el.addEventListener("error", () => {
      // Cleared so a later attempt is a fresh one. A page that lost
      // its connection for a moment should not be permanently unable
      // to split a key.
      loading = null;
      reject(new Error("the threshold signing code could not be loaded"));
    });
    document.head.appendChild(el);
  });
  return loading;
}

function toHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/* An index is a number in §7 and a 32-byte string underneath. §7.18
   gives every device a unique index `i ≥ 1` and the epoch record
   stores that number, so the number is the vocabulary here and the
   padding is this file's business. */
function identifierFor(index) {
  if (!Number.isInteger(index) || index < 1) throw new Error("an index is a whole number from 1");
  return index.toString(16).padStart(64, "0");
}

function indexOf(identifier) {
  return parseInt(identifier, 16);
}

/* §7.5 and §7.18: the dealer. One secret in, one share per index
   out, plus what everybody needs to check them.

   `commitments[0]` is the group key and `commitments[1]` is `a_1·G`,
   which is the `commitment` the epoch record carries. §7.4 requires
   `a_1` to be fresh randomness and never derived from the nsec; that
   is the implementation's to provide and it takes it from the
   platform's own generator. */
async function split(secret, opts) {
  const F = await load();
  const t = (opts && opts.t) || 2;
  const indices = (opts && opts.indices) || [1, 2];
  if (indices.length < t) throw new Error("there are fewer devices than the threshold needs");
  const identifiers = indices.map(identifierFor);
  const dealt = F.schnorr_FROST.trustedDealer(
    { min: t, max: indices.length }, identifiers, secret);
  const commitments = dealt.public.commitments.map(toHex);
  const groupPub = commitments[0];
  // §7.5: the group key must be the identity it was split from, and
  // this is where a parity mistake would show. An implementation
  // that negated the secret first arrives here with a group key that
  // is not the npub, and stops rather than wiping an nsec in favour
  // of shares of somebody else.
  const expected = toHex(F.schnorr.getPublicKey(secret));
  if (groupPub.slice(2) !== expected) {
    throw new Error("the split produced a key that is not this identity");
  }
  return {
    t,
    // x-only, which is what an npub is and what §7.5 compares.
    npub: groupPub.slice(2),
    // Compressed, which is what the share check needs.
    groupPub,
    // §7.4's `commitment`, singular, is this one.
    commitment: commitments[1],
    commitments,
    shares: indices.map((index) => ({
      index,
      share: toHex(dealt.secretShares[identifierFor(index)].signingShare),
      // What everybody else checks this share against.
      verifying: toHex(dealt.public.verifyingShares[identifierFor(index)]),
    })),
  };
}

/* §7.4's check, and §7.18's generalisation of it:
   `share_i·G == group_pub + commitment·i`.

   Written out rather than delegated, because it is the one piece of
   arithmetic the specification spells out and because a device
   about to wipe its nsec should check the share it is keeping with
   the formula it was given rather than with a library's opinion of
   what checking means.

   True only at `t = 2`. At `t = 3` the polynomial has a second
   coefficient and the check needs `+ commitment_2·i²`, which the
   epoch record has no field for — the general form below is what
   holds there, and the difference between the two answers is what
   the specification's own vectors record as the reason `t = 3` is
   not implementable as written. */
async function shareIsValid(entry) {
  const F = await load();
  const P = F.secp256k1.Point;
  const i = BigInt(entry.index);
  const share = BigInt("0x" + entry.share);
  const lhs = P.BASE.multiply(share);
  const rhs = P.fromHex(entry.groupPub).add(P.fromHex(entry.commitment).multiply(i));
  return lhs.toHex(true) === rhs.toHex(true);
}

// The general form, over as many commitments as the polynomial has:
// `share_i·G == Σ commitments[j]·i^j`. What §7.4's check is a
// one-coefficient special case of.
async function shareIsValidGeneral(entry) {
  const F = await load();
  const P = F.secp256k1.Point;
  const i = BigInt(entry.index);
  let sum = null;
  let power = 1n;
  for (const c of entry.commitments) {
    const term = P.fromHex(c).multiply(power);
    sum = sum ? sum.add(term) : term;
    power *= i;
  }
  return P.BASE.multiply(BigInt("0x" + entry.share)).toHex(true) === sum.toHex(true);
}

/* §7.18's signing, as the two rounds RFC 9591 defines.

   How many messages they cost is not decided here. A device that
   sends its own commitment alongside the message can have the other
   device's commitment and its signature share back in one reply; a
   device that asks for a commitment first and signs afterwards pays
   two round trips and has to keep a nonce between them. The second
   shape is the one where a nonce can be used twice, which discloses
   the share that used it, so the messaging layer chooses — and
   nothing here holds a nonce across a call. */
async function round1(entry) {
  const F = await load();
  const c = F.schnorr_FROST.commit({
    identifier: identifierFor(entry.index),
    signingShare: fromHex(entry.share),
  });
  return {
    // Held by the caller for exactly as long as one signature takes.
    nonces: c.nonces,
    commitments: c.commitments,
  };
}

/* Two lists of commitments meet here and they are not the same
   thing, so they do not share a name. `commitments` is the
   polynomial's — the group key and `a_1·G`, fixed for an epoch and
   written on the epoch record. `commitmentList` is this signature's —
   the hiding and binding pairs the signers just generated, good for
   one message and then gone. Calling both of them `commitments` cost
   an afternoon once. */
async function round2(entry) {
  const F = await load();
  return F.schnorr_FROST.signShare(
    { identifier: identifierFor(entry.index), signingShare: fromHex(entry.share) },
    publicPackage(entry),
    entry.nonces,
    entry.commitmentList,
    entry.message);
}

async function aggregate(entry) {
  const F = await load();
  return toHex(F.schnorr_FROST.aggregate(
    publicPackage(entry), entry.commitmentList, entry.message, entry.shares));
}

// What every operation above needs to know about the group, in the
// shape the implementation wants it. Rebuilt per call from the epoch
// record's own fields rather than kept, so there is one copy of it
// and it is the one on the record.
function publicPackage(entry) {
  const verifying = {};
  for (const v of entry.members) verifying[identifierFor(v.index)] = fromHex(v.verifying);
  return {
    signers: { min: entry.t, max: entry.members.length },
    commitments: entry.commitments.map(fromHex),
    verifyingShares: verifying,
  };
}

// §7.15: the one operation that puts the key back together, and the
// reason that section is the only one that reconstructs.
async function combine(entry) {
  const F = await load();
  return F.schnorr_FROST.combineSecret(
    entry.shares.map((s) => ({
      identifier: identifierFor(s.index),
      signingShare: fromHex(s.share),
    })),
    { min: entry.t, max: entry.members.length });
}

// BIP-340, against the x-only key an npub is. Anything this file
// produces should be checked with it before it is published, because
// a signature that does not verify is a post that silently never
// happened.
async function verify(sig, message, npub) {
  const F = await load();
  return F.schnorr.verify(fromHex(sig), message, fromHex(npub));
}

global.Frost = {
  load,
  split,
  shareIsValid,
  shareIsValidGeneral,
  round1,
  round2,
  aggregate,
  combine,
  verify,
  identifierFor,
  indexOf,
  toHex,
  fromHex,
};

})(typeof window !== "undefined" ? window : globalThis);
