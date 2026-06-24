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

1. **IR liveness** — an IR depth camera defeats photo/screen spoofing that fools
   RGB face auth. This is the single biggest reason this is viable for personal use.
2. **TPM-sealed keys** — private keys never exist as plaintext on disk. Disk
   theft or malware cannot clone credentials without the chip + a face match.
3. **Fail closed** — any Howdy error/timeout denies. The UV bit is never asserted
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
- **Least privilege:** daemon runs as the user. The PAM helper gets only what it
  needs for camera/model access (scoped setuid or a tight polkit action).
- **Glasses caveat:** Howdy enrollment is appearance-sensitive. Keep both
  glasses / no-glasses samples enrolled to avoid lockouts.

## Why NOT TPM-seal sudo

TPM secures *keys*; biometrics produce a *decision* (yes/no). `sudo` auth is a
boolean PAM gate with no key to release — so there is nothing for the TPM to
hold or unlock there. Sealing helps only where a decision releases a key (this
bridge; LUKS unlock). `sudo` stays plain PAM-Howdy. Sealing it would be theater.
