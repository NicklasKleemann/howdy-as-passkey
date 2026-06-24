//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"os"
	"testing"
)

// TestTPMECDSAGenerateSignVerify proves the TPM can do WebAuthn-style P-256
// ECDSA end to end: generate a key in the chip, sign a digest in the chip, and
// verify the DER signature against the returned public key with Go's ecdsa.
// This is the crypto foundation for TPM-backed passkeys.
func TestTPMECDSAGenerateSignVerify(t *testing.T) {
	if _, err := os.Stat(tpmDevicePath); err != nil {
		t.Skipf("no %s", tpmDevicePath)
	}

	blob, pub, err := tpmCreateECDSAKey()
	if err != nil {
		t.Skipf("cannot create TPM key (TPM access? in 'tss' group?): %v", err)
	}
	if pub == nil || pub.X == nil || pub.Y == nil {
		t.Fatal("nil public key from TPM")
	}

	msg := []byte("howdy-passkey-bridge in-chip signing test")
	digest := sha256.Sum256(msg)

	der, err := tpmECDSASign(blob, digest[:])
	if err != nil {
		t.Fatalf("tpm sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatal("signature did not verify against the TPM public key")
	}

	// A different digest must not verify against this signature.
	other := sha256.Sum256([]byte("different message"))
	if ecdsa.VerifyASN1(pub, other[:], der) {
		t.Fatal("signature verified for the wrong digest")
	}

	// Signing is non-deterministic but must verify each time.
	der2, err := tpmECDSASign(blob, digest[:])
	if err != nil {
		t.Fatalf("second tpm sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], der2) {
		t.Fatal("second signature did not verify")
	}
}
