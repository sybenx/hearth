# hearth

Voice chat app for friends.

Hearth is a voice and chat client for a small group of people who already know each other. It is meant for ten to twenty people, with no public directory and no discovery. Members can text chat and join a voice call, and share a screen or camera in the call. Calls are a mesh over WebRTC, so they work for a handful of people (the notes say seven at the outside).

## What it runs on

- A web page you can add to your home screen (it has a web manifest and a service worker). It is phone first.
- A [bothy](https://github.com/sybenx/bothy) relay, which one person in the group hosts. The relay holds the group's members and its chat history, and carries the call signalling. Audio and video go directly between members, not through the relay.
- Identity is a nostr keypair. A new member only picks a name, and the key is made for them.
- Calls use public STUN servers to connect.

There is no backend of its own. Everything else is in the relay or on your device.

## Using it

- Open https://sybenx.github.io/hearth/ and follow an invite link from the person who runs your group's relay. A relay also serves its own copy of the app.
- It is plain static files with no build step, so any static file server will do. You still need a bothy relay to connect to.

## Layout

- `index.html`, `app.js`: the app and its styles
- `sw.js`: service worker, used only for notifications
- `keyxfer.js`: moving a key between your own devices by QR code or link (vectors in `keyxfer-vectors.json`, checked by `vectors.html`)
- `frost.js`: splitting a key across your own devices (vectors in `frost-vectors.json`)
- `reference/`: design mocks and notes on push notifications for the relay
- `vendor/`: bundled third party libraries
- `.github/workflows/pages.yml`: deploys the site to GitHub Pages on push to `main`

Built for my own use. It works on my setup. No support promised.
