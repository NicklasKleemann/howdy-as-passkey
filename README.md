# howdy-passkey-bridge

Use [Howdy](https://github.com/boltgolt/howdy) face authentication as a **passkey** (WebAuthn/FIDO2) that browsers and apps recognize.

Linux has no native platform authenticator - the role Windows Hello / macOS Touch ID fill. This bridges the gap: a virtual FIDO2/CTAP2 authenticator whose user-verification step is your Howdy face match.

> **Status:** working. Verified in Chrome on [webauthn.io](https://webauthn.io) and GitHub - passkey registration and sign-in with `uv=1`, gated by a live Howdy scan, no sudo at runtime. Personal-use project, **not security-audited** - see [Security](#security).

## How it works

```
Browser (WebAuthn)
   │  CTAP2 over USB-HID (virtual device via USB/IP)
   ▼
bridge daemon  (runs as your user, no sudo)
   ├─ CTAP2: makeCredential / getAssertion / getInfo
   ├─ key store ── encrypted file vault  (TPM sealing planned)
   └─ user-verification ──► Howdy (PAM) ──► face match? yes/no
```

The browser runs a normal WebAuthn ceremony and sees a standard USB security key. When it asks for user verification, the daemon runs a Howdy face check (`pamtester howdy-only`). Match → it signs the assertion. Fails closed on any error.

## Quickstart (Arch / CachyOS)

```sh
git clone https://github.com/NicklasKleemann/howdy-passkey-bridge
cd howdy-passkey-bridge

./scripts/setup-env.sh        # deps, howdy-only PAM stack, usbip group + udev rule, vhci module
./scripts/install-service.sh  # build, install to ~/.local/bin, set up the systemd user service
                              # (prompts for a vault passphrase - remember it; it encrypts your keys)
# log out and back in once (activates the 'usbip' group), then:
systemctl --user start howdy-passkey-bridge.service
```

Then register a passkey on any site. In the browser dialog pick the **security key / USB** option (we present over USB transport) - Howdy prompts for your face. The service autostarts on every login thereafter.

Manage it:

```sh
systemctl --user status howdy-passkey-bridge      # is it running?
journalctl --user -u howdy-passkey-bridge -f      # live logs (CTAP traffic, Howdy prompts)
systemctl --user stop howdy-passkey-bridge        # stop
```

Other distros: install the equivalents of the packages listed in `scripts/setup-env.sh` (it is written for Arch/pacman).

## Prerequisites

You bring these; the setup script does not install them for you:

- **Howdy**, installed and enrolled (`sudo howdy add`). Distro-specific install - see [howdy](https://github.com/boltgolt/howdy).
- **An IR depth camera.** RGB-only webcams are photo/screen-spoofable; do not trust this for real accounts without IR liveness.
- **TPM 2.0** recommended for the planned key-sealing step. Today keys live in a passphrase-encrypted file vault - see [docs/security.md](docs/security.md).
- Linux with the `vhci-hcd` kernel module available (mainline; loaded by setup).

## Testing

```sh
. scripts/env.sh
( cd src/virtual-fido && go test ./ctap/ ./cmd/howdy-bridge/ )   # unit tests, no hardware
```

Unit tests cover the fork's CTAP changes (UV flag on makeCredential/getAssertion, GetInfo advertising uv + platform, graceful errors instead of panics) and the approver (fail-closed PAM logic, action routing, vault round-trip) - with a mocked PAM call, so no camera is needed.

End-to-end (needs the IR camera, an enrolled face, and the `usbip` group active - performs a live scan):

```sh
sg usbip -c scripts/test-e2e.sh
```

It attaches the authenticator, drives a real `makeCredential` with libfido2, asserts `uv=1`, and verifies it.

## Security

Read [docs/security.md](docs/security.md) before trusting this with real accounts. Short version: built for personal use on a machine with an IR depth camera. It runs unprivileged (no sudo); the only security gate is the Howdy face check, which fails closed. Keys are currently in a passphrase-encrypted file vault (not yet TPM-sealed). **Not hardware-attested, not security-reviewed.** Keep a second 2FA method on any account you add it to.

## Built on

- [bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido) - the CTAP2/U2F + USB/IP authenticator this forks and patches (MIT; license preserved at `src/virtual-fido/LICENSE`). See [DESIGN.md](DESIGN.md) for what the fork changes and why.
- [Howdy](https://github.com/boltgolt/howdy) - the face-recognition PAM module providing user verification.

## License

MIT - see [LICENSE](LICENSE). Bundled `src/virtual-fido/` retains its own MIT license (© 2022 BulwarkID).
