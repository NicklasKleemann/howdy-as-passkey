//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

// TestTPMSealUnsealRoundTrip seals a random secret to the real TPM and unseals
// it. Skips cleanly when there is no TPM or no access to it (e.g. not in the
// 'tss' group), so it is safe in CI; run it under `sg tss` to exercise the chip.
func TestTPMSealUnsealRoundTrip(t *testing.T) {
	if _, err := os.Stat(tpmDevicePath); err != nil {
		t.Skipf("no %s", tpmDevicePath)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	blob, err := tpmSeal(secret)
	if err != nil {
		t.Skipf("cannot seal (TPM access? in 'tss' group?): %v", err)
	}
	if len(blob) < 8 {
		t.Fatalf("sealed blob implausibly short: %d bytes", len(blob))
	}

	got, err := tpmUnseal(blob)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, secret)
	}

	// A blob from this TPM must not unseal after corruption (sanity that we are
	// really gated on the sealed data, not echoing input).
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0xff
	if out, err := tpmUnseal(bad); err == nil && bytes.Equal(out, secret) {
		t.Fatal("corrupted blob still unsealed to the secret")
	}
}
