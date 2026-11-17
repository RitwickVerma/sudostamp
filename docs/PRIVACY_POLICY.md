# SudoStamp Privacy Policy

**Effective date:** 16 November 2026 (applies to SudoStamp 1.7 and later; earlier versions: the
same, without pairing by QR code and without the website)
**Developer:** Ritwick Verma — verma1997@gmail.com
**App:** SudoStamp (`com.ritwick.sudostamp`), free and open source (MIT),
source at https://gitlab.com/ritwick7/sudostamp

## The short version

SudoStamp does not collect, send or share any personal data. It has no accounts, no ads, no
analytics, no crash reporting and no internet connection of its own. It talks only to the computers
you pair it with, on your own local network.

## What the app handles, and where it stays

| What | Why | Where it goes |
|---|---|---|
| Your fingerprint | Android's biometric prompt confirms it is you before each approval. | Never seen by the app: Android checks the fingerprint in its secure hardware and only tells the app "yes" or "no". |
| Signing keys | One per paired computer, made inside the phone's secure hardware (Android Keystore). | Never leave the phone; cannot be exported, even by the app. |
| Paired computers | The name each computer gave when pairing, when it was paired, and the address it paired from, so approvals can say which computer is asking. | Stored in the app's private storage on the phone; deleted when you remove that computer or uninstall the app. Excluded from Android backup and device transfer. |
| Requests from your computers | A computer you paired sends a random 32-byte challenge; the phone signs it after your fingerprint and sends the signature back to that computer. | Over your local network only, directly between the phone and that computer. Nothing is stored. |
| Local network | The app listens on TCP port 7777 for paired computers, and serves only devices on the same Wi-Fi or Ethernet network. While you pair a computer it announces itself on that network (mDNS) so the computer can find it. | Nothing goes to the internet. |
| Notifications | Shows "Approve sudo?" for each request, and an ongoing notice while the listener runs (Android requires it). | — |
| Pairing codes | A computer's pairing QR code holds a one-time secret and the computer's name. Your camera app opens it as a link to SudoStamp, which uses the secret once, over your local network, to pair with that computer. | Never stored or sent anywhere else; it stops working after two minutes. If the link opens in a browser instead, it stays in the part of the link that browsers never send (see "The website" below). |

## What the app does not do

No data is sold, shared, or sent to the developer or any third party. There are no third-party
libraries in the app at all. The app does not access contacts, location, files, the camera, the
microphone or your accounts.

## The website

https://sudostamp.ritwickverma.dev, where this policy and the pairing link live, is a static site
served by Cloudflare Pages. It sets no cookies, runs no analytics and loads nothing from anyone
else. Cloudflare, which serves it, sees what any web server sees (your IP address and browser) and
keeps it under its own policy. The pairing page reads the secret only in your browser, to offer an
"Open in SudoStamp" button, and removes it from the address bar at once.

## Children

SudoStamp is a tool for computer administrators and is not directed at children.

## Changes

Changes to this policy are made in this file, in the public repository, with the date above
updated; the history is visible in the repository.

## Contact

verma1997@gmail.com, or a confidential issue at https://gitlab.com/ritwick7/sudostamp/-/issues.
