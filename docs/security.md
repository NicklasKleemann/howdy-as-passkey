# Security model

This is homemade authenticator software. Read before trusting it with real
accounts.

## Threat model & comparison to Windows Hello

Windows Hello has two layers, a biometric and a TPM key-binding. This project
copies both:

| Layer | Windows Hello | This project |
|---|---|---|
| Biometric | face/fingerprint | Howdy + **IR depth camera** |
| Key binding | keys in TPM | keys generated and signed in **TPM 2.0** |

Hello's documented bypasses (spoofed USB cameras, CVE-2021-34466; fingerprint
defeats) target the biometric layer, not the TPM key-binding. This project
matches both for personal use.

### What protects you

1. **IR liveness** - an IR depth camera defeats photo/screen spoofing that fools
   RGB face auth.
2. **TPM-bound keys (when present)** - in TPM mode the vault key is sealed to the
   TPM, and each passkey's private key is generated inside the TPM and signs
   inside it, so the private key never leaves the chip and the vault cannot be
   decrypted on another machine. Without a TPM, keys are software-backed and the
   vault uses passphrase encryption.
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
bridge; LUKS unlock), so `sudo` stays plain PAM-Howdy.
