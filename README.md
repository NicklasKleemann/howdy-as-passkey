# howdy-passkey-bridge

Use [Howdy](https://github.com/boltgolt/howdy) face authentication as a **passkey** (WebAuthn/FIDO2) that browsers and apps recognize.

Linux has no native platform authenticator (the role Windows Hello / macOS Touch ID fill). This bridges the gap: a virtual FIDO2/CTAP2 authenticator whose user-verification step is your Howdy face match, with private keys sealed in your TPM.

> **Status:** design phase. No working code yet. See [DESIGN.md](DESIGN.md).

## How it works

```
Browser (WebAuthn)
   │  CTAP2 over USB-HID (virtual device via USB/IP)
   ▼
bridge daemon
   ├─ CTAP2: makeCredential / getAssertion / getInfo
   ├─ key store ── sealed to TPM 2.0
   └─ user-verification ──► Howdy (PAM) ──► face match? yes/no
```

Browser does a normal WebAuthn ceremony and sees a standard roaming USB security key. When it asks for user verification, the daemon runs a Howdy face check. Match → sign the assertion with a TPM-sealed key.

## Prerequisites

You bring these; the setup script does not install them for you:

- **Howdy**, installed and enrolled (`sudo howdy add`). Distro-specific install — see [howdy](https://github.com/boltgolt/howdy).
- **An IR depth camera.** RGB-only webcams are photo/screen-spoofable; do not trust this for real accounts without IR liveness.
- **TPM 2.0** strongly recommended (key sealing). Without it, keys fall back to an encrypted file vault — weaker, see [docs/security.md](docs/security.md).
- Linux with the `vhci-hcd` kernel module available (mainline; loaded by setup).

`scripts/setup-env.sh` handles the rest: toolchain, the `howdy-only` PAM stack
(created if absent), the kernel module, and project-local Go/Python envs. It is
written for **Arch/pacman**; other distros need the equivalent packages (noted
in the script).

## Testing

```sh
. scripts/env.sh
( cd src/virtual-fido && go test ./ctap/ ./cmd/howdy-bridge/ )   # unit tests (no hardware)
```

Unit tests cover the fork's CTAP changes (UV flag on makeCredential/getAssertion,
GetInfo advertising uv + platform, graceful errors instead of panics) and the
approver (fail-closed PAM logic, action routing, vault round-trip) — all with a
mocked PAM call, so no camera is needed.

End-to-end (needs the IR camera, an enrolled face, and the `usbip` group active —
performs a live scan):

```sh
sg usbip -c scripts/test-e2e.sh
```

It attaches the authenticator, drives a real `makeCredential` with libfido2,
asserts the result is `uv=1`, and verifies it.

## Security

Read [docs/security.md](docs/security.md) before trusting this with real accounts. Short version: built for personal use on a machine with an IR depth camera + TPM 2.0. Not hardware-attested. Not security-reviewed.

## License

TBD — must verify upstream `bulwarkid/virtual-fido` license before publishing the fork.
