package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bulwarkid/virtual-fido/fido_client"
)

// fakePAM returns a pamAuthFunc with the given outcome.
func fakePAM(out []byte, err error) pamAuthFunc {
	return func(ctx context.Context, service, user string) ([]byte, error) {
		return out, err
	}
}

func TestVerifyFailClosed(t *testing.T) {
	cases := []struct {
		name string
		pam  pamAuthFunc
		want bool
	}{
		{"success", fakePAM([]byte("Identified face"), nil), true},
		{"nonzero exit", fakePAM([]byte("Authentication failure"), errors.New("exit status 1")), false},
		{"missing binary", fakePAM(nil, errors.New(`exec: "pamtester": executable file not found`)), false},
		{"empty error", fakePAM(nil, errors.New("boom")), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &HowdyClient{pamService: "howdy-only", user: "tester", pamAuth: tc.pam}
			if got := c.verify("test"); got != tc.want {
				t.Fatalf("verify() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A PAM call that times out (deadline exceeded) must fail closed, never approve.
func TestVerifyTimeoutFailsClosed(t *testing.T) {
	deadlineErr := func(ctx context.Context, service, user string) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}
	c := &HowdyClient{pamService: "howdy-only", user: "tester", pamAuth: deadlineErr}
	if c.verify("timeout") {
		t.Fatal("verify() returned true on DeadlineExceeded; must fail closed")
	}
}

func TestApproveClientActionRouting(t *testing.T) {
	called := 0
	approve := func(ctx context.Context, service, user string) ([]byte, error) {
		called++
		return []byte("ok"), nil
	}
	c := &HowdyClient{pamService: "howdy-only", user: "tester", pamAuth: approve}

	known := []fido_client.ClientAction{
		fido_client.ClientActionFIDOMakeCredential,
		fido_client.ClientActionFIDOGetAssertion,
		fido_client.ClientActionU2FRegister,
		fido_client.ClientActionU2FAuthenticate,
	}
	for _, a := range known {
		if !c.ApproveClientAction(a, fido_client.ClientActionRequestParams{RelyingParty: "example.com", UserName: "u"}) {
			t.Fatalf("action %d: expected approval", a)
		}
	}
	if called != len(known) {
		t.Fatalf("expected %d PAM calls, got %d", len(known), called)
	}

	// Unknown action must be denied WITHOUT invoking PAM (fail closed, no scan).
	before := called
	if c.ApproveClientAction(fido_client.ClientAction(0xFE), fido_client.ClientActionRequestParams{}) {
		t.Fatal("unknown action approved; must deny")
	}
	if called != before {
		t.Fatal("unknown action triggered a PAM call; must short-circuit")
	}
}

func TestVaultRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := &HowdyClient{vaultPath: filepath.Join(dir, "vault.json"), passphrase: "secret"}

	// Missing file -> nil, no error/panic.
	if got := c.RetrieveData(); got != nil {
		t.Fatalf("RetrieveData on missing vault = %v, want nil", got)
	}

	payload := []byte("encrypted-blob")
	c.SaveData(payload)
	if got := c.RetrieveData(); string(got) != string(payload) {
		t.Fatalf("RetrieveData = %q, want %q", got, payload)
	}

	// Vault must be written 0600 — never group/world readable.
	info, err := os.Stat(c.vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("vault perms = %o, want 600", perm)
	}

	if c.Passphrase() != "secret" {
		t.Fatalf("Passphrase() = %q", c.Passphrase())
	}
}

// Guard against a regression where the timeout backstop is removed entirely.
func TestVerifyTimeoutConstantSane(t *testing.T) {
	if howdyVerifyTimeout <= 0 || howdyVerifyTimeout > 2*time.Minute {
		t.Fatalf("howdyVerifyTimeout = %s, expected a sane positive backstop", howdyVerifyTimeout)
	}
}
