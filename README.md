# howdy-passkey-bridge

Use [Howdy](https://github.com/boltgolt/howdy) face authentication as a **passkey** (WebAuthn/FIDO2) that browsers and apps recognize.

Linux has no native platform authenticator, the role Windows Hello and macOS Touch ID fill. This bridges the gap: a virtual FIDO2/CTAP2 authenticator whose user verification step is your Howdy face match.

> **Status:** working. Verified in Chrome on [webauthn.io](https://webauthn.io) and GitHub, doing passkey registration and sign-in with `uv=1`, gated by a live Howdy scan, with no sudo at runtime. On a machine with a TPM the vault key is sealed to it (auto-detected). This is a personal-use project and is **not security audited** (see [Security](#security)).

## How it works

```
Browser (WebAuthn)
   │  CTAP2 over USB-HID (virtual device via USB/IP)
   ▼
bridge daemon  (runs as your user, no sudo)
   ├─ CTAP2: makeCredential / getAssertion / getInfo
   ├─ key store ── vault key sealed to the TPM (or a disk passphrase)
   └─ user verification ──► Howdy (PAM) ──► face match? yes/no
```

The browser runs a normal WebAuthn ceremony and sees a standard USB security key. When it asks for user verification, the daemon runs a Howdy face check (`pamtester howdy-only`). On a match it signs the assertion. It fails closed on any error.

## Quickstart (Arch / CachyOS)

```sh
git clone https://github.com/NicklasKleemann/howdy-passkey-bridge
cd howdy-passkey-bridge

./scripts/setup-env.sh        # deps, howdy-only PAM stack, usbip group + udev rule, vhci module
./scripts/install-service.sh  # build, install to ~/.local/bin, set up the systemd user service
                              # (it prompts for a vault passphrase; remember it, it encrypts your keys)
# log out and back in once so the 'usbip' group takes effect, then:
systemctl --user start howdy-passkey-bridge.service
```

Then register a passkey on any site. In the browser dialog pick the **security key / USB** option (we present over USB transport), and Howdy prompts for your face. The service autostarts on every login thereafter.

Manage it:

```sh
systemctl --user status howdy-passkey-bridge      # is it running?
journalctl --user -u howdy-passkey-bridge -f      # live logs (CTAP traffic, Howdy prompts)
systemctl --user stop howdy-passkey-bridge        # stop
```

Other distros: install the equivalents of the packages listed in `scripts/setup-env.sh`, which is written for Arch/pacman.

## Prerequisites

You bring these; the setup script does not install them for you:

- **Howdy**, installed and enrolled (`sudo howdy add`). The install is distro specific (see [howdy](https://github.com/boltgolt/howdy)).
- **An IR depth camera.** RGB-only webcams are photo/screen-spoofable; do not trust this for real accounts without IR liveness.
- **TPM 2.0** (optional). If present, `install-service.sh` seals the vault key to it and the bridge auto-detects it at startup; otherwise the vault uses passphrase encryption on disk. See [docs/security.md](docs/security.md).
- Linux with the `vhci-hcd` kernel module available (mainline; loaded by setup).

## Testing

```sh
. scripts/env.sh
( cd src/virtual-fido && go test ./ctap/ ./cmd/howdy-bridge/ )   # unit tests, no hardware
```

The unit tests cover the fork's CTAP changes (the UV flag on makeCredential and getAssertion, GetInfo advertising uv and platform, graceful errors instead of panics) and the approver (fail-closed PAM logic, action routing, vault round-trip). They use a mocked PAM call, so no camera is needed.

The end-to-end test needs the IR camera, an enrolled face, and the `usbip` group active, and it performs a live scan:

```sh
sg usbip -c scripts/test-e2e.sh
```

It attaches the authenticator, drives a real `makeCredential` with libfido2, asserts `uv=1`, and verifies the result.

## Security

Read [docs/security.md](docs/security.md) before trusting this with real accounts. In short: it is built for personal use on a machine with an IR depth camera. It runs unprivileged (no sudo), and the only security gate is the Howdy face check, which fails closed. On a machine with a TPM the vault key is sealed to it, so the vault cannot be decrypted on another machine; without a TPM the vault is passphrase-encrypted on disk. Clearing or replacing the TPM loses the vault, so keep the pre-TPM backup the migration writes (`vault.json.pre-tpm.bak`). It is **not hardware attested and not security reviewed.** Keep a second 2FA method on any account you add it to.

## Built on

- [bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido), the CTAP2/U2F and USB/IP authenticator this forks and patches (MIT; license preserved at `src/virtual-fido/LICENSE`). See [DESIGN.md](DESIGN.md) for what the fork changes and why.
- [Howdy](https://github.com/boltgolt/howdy), the face-recognition PAM module that provides user verification.

## License

MIT. See [LICENSE](LICENSE). The bundled `src/virtual-fido/` keeps its own MIT license (© 2022 BulwarkID).
