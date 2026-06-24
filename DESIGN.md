# Design

Living record of architecture and decisions. Update as things change.

## Goal

Give Linux a Howdy-backed platform authenticator so browsers/apps treat Howdy
face auth as a passkey. Open-source it — fills a real gap (no native platform
authenticator on Linux).

## Architecture

Virtual CTAP2 authenticator daemon, exposed to the browser as a USB security
key. Browsers already trust roaming USB authenticators with zero config, so no
browser-side changes needed.

```
Browser (WebAuthn)
   │  CTAP2 over USB-HID
   ▼
bridge daemon
   ├─ CBOR: authenticatorMakeCredential / GetAssertion / GetInfo / clientPIN
   ├─ key store (ES256 keypairs)  ── sealed to TPM 2.0
   └─ user-verification hook ──► Howdy (PAM) ──► yes/no
```

### Device exposure: USB/IP (chosen) vs uhid

- **USB/IP** (`vhci-hcd` kernel module + `usbip` userspace) — attach a virtual
  USB device to localhost; browser enumerates it like a real YubiKey. Robust,
  no browser config. **Chosen.**
- **uhid** — present a raw HID device with FIDO usage page `0xF1D0`. Needs udev
  rules for browser access. Fallback only.

### Base project — DECISION: hard fork (audited 2026-06-24)

Fork [`bulwarkid/virtual-fido`](https://github.com/bulwarkid/virtual-fido) (Go,
MIT). Implements CTAP2/U2F (CBOR), USB/IP virtual device, encrypted vault, and an
approval callback. We **vendor and patch it** rather than import as a library.
Base commit: `512d8a3` (upstream HEAD, ~2024-08, effectively unmaintained).

A 3-angle audit decided fork over library-dependency, unanimously:

1. **UV bit (hard blocker).** The approver-success path sets only UP=1, never
   UV=1 (ctap.go:239/360); UV is set only under CTAP PIN auth (ctap.go:227/344).
   No public API to force it. Passkey/passwordless RPs require `uv=1`, so a
   library integration produces assertions they reject. Must edit ctap.go to set
   UV on a verified Howdy approval.
2. **TPM in-chip signing.** Keys are concrete `*ecdsa.PrivateKey` dereferenced
   directly at sign time (cose.go:88, crypto.go:85, ctap.go:250/364) — no
   `crypto.Signer` seam. Seal-at-rest is library-doable via
   `ClientDataSaver.Passphrase()`, but key-never-leaves-TPM signing requires
   refactoring cose/crypto to `crypto.Signer`. (The `secretEncryptionKey [32]byte`
   does NOT protect the resident-key vault — `Passphrase()` does.)
3. **Maintenance.** ~2 yrs stale, beta, "APIs may change," 36 open issues, and
   unmerged security PRs we'd have to carry anyway.

**Security PRs to cherry-pick from upstream** (open, ignored by maintainer):
- #51 AES-CBC panic on non-block-aligned input (remote DoS)
- #53 data races in CTAP message handling
- #52 non-constant-time PIN comparison (timing attack)
- #54 nil-deref crash on MakeCredential without rp
Also harden the ~18 `panic()`-as-error-handling sites (several peer-reachable).

**Attestation:** format hardcoded to "packed" (ctap.go:259); add none/self
selection. Minor.

> License: MIT — fork/modify/redistribute OK; preserve BulwarkID copyright notice.

### Howdy hook

The approver (`cmd/howdy-bridge/approver.go`) gates every ceremony by running
`pamtester howdy-only <user> authenticate` against the face-only PAM service
`/etc/pam.d/howdy-only`. Exit 0 = face matched → approve (and set UV); anything
else → deny.

- Use the PAM route (via pamtester), **not** Howdy's internal compare — inherits
  Howdy's full config (timeout, certainty, dark threshold, retries).
- **Fail closed:** non-zero exit, missing binary, or a 30s backstop timeout all
  return false. Never default-allow.
- Runs as the unprivileged user (member of `video`); no root needed for the face
  check.

### Privilege model — no sudo

The daemon runs fully unprivileged. The only root-needing operation, writing the
vhci `attach`/`detach` sysfs controls, is delegated to a `usbip` group via
`scripts/70-howdy-passkey-vhci.rules`; the installer adds the user to that group.
No sudoers entry. (An earlier NOPASSWD-sudo approach was rejected: its
`usbip attach *` wildcard was a privilege-escalation path.)

### Key storage

Seal passkey private keys to **TPM 2.0** (`/dev/tpmrm0`). Signing happens inside
the chip; keys never sit on disk in plaintext. Go binding via `tpm2-tss`.
virtual-fido's file vault alone is not enough for real accounts.

## Target machine (probed 2026-06-24)

| Component | State |
|---|---|
| OS | CachyOS (Arch), AMD, GNOME/Wayland, Lenovo Yoga |
| git | 2.54.0 ✓ |
| Howdy | `howdy-git` (AUR), IR cam `/dev/video2` ✓ |
| PAM hook | `/etc/pam.d/howdy-only` exists ✓ |
| TPM | 2.0, `/dev/tpmrm0` ✓ |
| IR depth camera | yes ✓ (strong liveness) |
| vhci-hcd | module on disk, not loaded |
| go | not installed |
| usbip | not installed |
| tpm2-tools / tpm2-tss | not installed |

## Environment isolation

`scripts/setup-env.sh` does one-time setup; `scripts/env.sh` is sourced per shell.

- **Project-local (isolated):** Go module cache, build cache, and binaries live in
  `./.go` and `./bin` (`GOPATH`/`GOCACHE`/`GOMODCACHE`/`GOBIN` overridden by
  `env.sh`); deps are vendored (`GOFLAGS=-mod=vendor`). Python helper deps live in
  `./.venv` (uv). Nothing leaks to `~/go` or system site-packages.
- **System (cannot be isolated):** the `go` compiler + `gcc` (toolchain, not deps),
  `usbip` + `tpm2-tss` (kernel-facing C libs the cgo build links against), and
  `vhci-hcd` (kernel module). A compiler, C libs, and a kernel module have no venv
  equivalent.

Run `scripts/setup-env.sh` once, then `. scripts/env.sh` in each shell before building.

## Integration points (virtual-fido)

Fork lives in `src/virtual-fido/` (MIT — fork/modify/redistribute OK, keep their
copyright notice). Two interfaces in `fido_client/fido_client.go` are all we touch:

- **`ClientRequestApprover.ApproveClientAction(action, params) bool`** — the Howdy
  gate. `action` 2 = MakeCredential, 3 = GetAssertion (the WebAuthn ceremonies);
  `params` has RelyingParty + UserName for the prompt. Implement to call the
  `howdy-only` PAM helper; return `true` only on a real match, `false` on any
  error/timeout (fail closed).
- **`ClientDataSaver` (`SaveData`/`RetrieveData`/`Passphrase`)** + the
  `secretEncryptionKey [32]byte` arg to `NewDefaultClient` — key storage. The
  vault is encrypted with that key; **seal the key to the TPM** so the vault only
  decrypts with chip + face. File-based saver first, TPM second.

Wiring: `fido_client.NewDefaultClient(... approver, saver)` → `virtual_fido.Start(client)`.

> Build note: `env.sh` sets `GOFLAGS=-mod=vendor` but the upstream has no
> `vendor/` yet — run `go mod vendor` after the first fork build, or unset the
> flag for the initial bring-up build.

## Roadmap

1. ✅ Env setup (go/usbip/tpm tools, vhci-hcd loaded + persisted, venv).
2. ✅ Clone virtual-fido, audit, decide fork.
3. ✅ Absorb the fork: nested `.git` dropped, base `512d8a3` recorded; deps
   vendored; demo builds (`bin/vfido-demo`). Baseline verified 2026-06-24: device
   attaches via USB/IP, enumerates as HID with FIDO usage page `0xF1D0`
   (`lsusb` → "No Company Virtual FIDO", hidraw created), Howdy auths the attach.
   Known-good before any edit. NOTE: the demo's stdin y/n approver panics under
   nohup (no tty) — our HowdyApprover removes that dependency (step 4).
4. ✅ **UV fix** (the blocker): set `authDataFlagUserVerified` on a verified
   approval in ctap.go (both ceremonies) + advertise `uv` in GetInfo. Implemented
   `cmd/howdy-bridge` with a `pamtester`-based approver (fail-closed) and a
   file-backed vault. Runs with no sudo (usbip group + udev rule).
   Verified 2026-06-24 via libfido2: `fido2-cred -M -v` → authData flags `0x45`
   (UP+UV+AT), `fido2-cred -V` (uv required) passes. Live Howdy gated the create.
5. Browser end-to-end: `navigator.credentials.create()` + `.get()` with `uv=1`
   on webauthn.io (USER to eyeball in Chrome — the headless libfido2 path is green).
6. Security patches: cherry-pick PRs #51/#52/#53/#54; harden remaining panic
   sites. (Done so far: HandleMessage no longer panics on empty/unknown commands.)
7. TPM: seal-at-rest via `ClientDataSaver.Passphrase()` first; then refactor
   cose/crypto to `crypto.Signer` for in-chip signing.
8. systemd user service, attestation none/self option, docs, publish.
