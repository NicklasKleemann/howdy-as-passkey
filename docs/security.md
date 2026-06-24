# Security model

This is homemade authenticator software. Read before trusting it with real
accounts.

## Threat model & comparison to Windows Hello

Windows Hello = two layers. This project copies both:

| Layer | Windows Hello | This project |
|---|---|---|
| Biometric (the weak, bypassable part) | face/fingerprint, secure path | Howdy + **IR depth camera** |
| Key binding (the part that holds) | keys in TPM | keys sealed to **TPM 2.0** |

Hello's documented bypasses (e.g. spoofed USB cameras, CVE-2021-34466;
fingerprint-sensor defeats) all target the *biometric* layer. Its TPM
key-binding is what actually protects credentials. We match both layers for
personal use.

### What protects you

1. **IR liveness** - an IR depth camera defeats photo/screen spoofing that fools
   RGB face auth. This is the single biggest reason this is viable for personal use.
2. **TPM-sealed vault (when present)** - the vault key is sealed to the TPM, so
   the encrypted vault on disk cannot be decrypted on another machine or without
   this TPM. Without a TPM the vault falls back to passphrase encryption. Note:
   keys are decrypted into memory to sign; in-chip signing, where the private key
   never leaves the TPM, is not yet implemented.
3. **Fail closed** - any Howdy error/timeout denies. The UV bit is never asserted
   without a real match.

### What this is NOT

- **Not hardware-attested.** Howdy's model runs in userspace; there is no secure
  enclave guarding the camera path. Do not make hardware-attestation claims.
- **Not security-reviewed.** Personal-use tool. Do not deploy as auth for other
  people without a real review.
- **Root is game over.** An attacker with root can rewrite the PAM stack or the
  daemon. TPM sealing defends data-at-rest / offline theft, not a live rooted box.

## Design rules

- **UV honesty:** when the daemon asserts user-verification to a relying party,
  that assertion must reflect a real, current Howdy match. No caching a "yes".
  Each ceremony runs `pamtester howdy-only <user> authenticate` and fails closed
  on any non-success (non-zero exit, timeout, missing binary).
- **Least privilege - the daemon runs fully unprivileged, no sudo.** Howdy auth
  works as the user (member of `video`). The one operation that would need root,
  writing the vhci `attach`/`detach` sysfs controls, is granted to a dedicated
  `usbip` group via a udev rule (`scripts/70-howdy-passkey-vhci.rules`); the user
  joins that group. There is no sudoers entry.
  - Residual risk: members of the `usbip` group can attach/detach USB/IP devices
    (e.g. a rogue HID). Keep the group limited to the human user(s) who run the
    bridge. This is strictly better than the rejected alternative - a NOPASSWD
    sudo rule for `usbip attach *`, whose wildcard let any local code attach an
    arbitrary remote device as root (a privilege-escalation path).
- **Robustness:** unknown/empty CTAP commands return a spec error, never panic -
  a single malformed frame from any process on the USB bus must not crash the
  authenticator. (Upstream panicked; see the fork's ctap.go hardening.)
- **Glasses caveat:** Howdy enrollment is appearance-sensitive. Keep both
  glasses / no-glasses samples enrolled to avoid lockouts.

## Why NOT TPM-seal sudo

TPM secures *keys*; biometrics produce a *decision* (yes/no). `sudo` auth is a
boolean PAM gate with no key to release - so there is nothing for the TPM to
hold or unlock there. Sealing helps only where a decision releases a key (this
bridge; LUKS unlock). `sudo` stays plain PAM-Howdy. Sealing it would be theater.
