# Security

Thumbdesk runs on machines people care about, so we want to hear about anything that looks wrong. This page says how to reach us and what to expect.

## Reporting a problem

Two ways, pick whichever suits the report:

- **Email support@thumbdesk.com** with "Security" in the subject. Use this for anything exploitable or anything you would rather not discuss in public. If the report is sensitive, ask for a PGP key in your first message and we will send one before you share details. GitHub's private "Report a vulnerability" form on this repository reaches us the same way.
- **Open an issue** on [yashagldit/Thumbdesk](https://github.com/yashagldit/Thumbdesk/issues) for anything that can be discussed in the open: a hardening suggestion, a question about the design, or a place where [docs/protocol.md](./docs/protocol.md) and the published code disagree.

We read every report and reply within five business days. We will tell you what we found, keep you updated while we fix it, and credit you in the release notes if you want. We ask for a reasonable window, typically 90 days, before publication. Good-faith research under these terms is welcome; we will not pursue action against it.

## Scope

- The host agent published from this repository, on every platform.
- The Thumbdesk apps for iOS and Android.
- The backend at `api.thumbdesk.com` and `api.pocketshell.app`, and the website.

The agent's trust design is written up in [docs/protocol.md](./docs/protocol.md) and on [thumbdesk.com/security](https://thumbdesk.com/security/), and the source for pairing, signaling, the backend client and self-update is in [crates/host-core](./crates/host-core/). Reports that show a gap between those documents and what the code does are as welcome as exploits.

## Supported versions

The current release is the supported one. Installed agents update themselves to it; the `thumbdesk update` command does the same on demand. Fixes are not backported to older versions.

## Verifying what you install

Every release asset ships with a SHA-256 checksum and a Sigstore cosign signature bound to this repository's release workflow; the macOS app is notarized; the npm packages carry build provenance. The commands are in the [README](./README.md#verify-a-release-yourself).
