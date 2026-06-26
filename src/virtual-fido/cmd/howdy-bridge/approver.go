package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/bulwarkid/virtual-fido/fido_client"
)

// howdyVerifyTimeout bounds a single face-auth attempt. Howdy has its own
// internal timeout; this is a backstop so a wedged check can never hang the
// authenticator (which would read as "approval pending" forever).
const howdyVerifyTimeout = 30 * time.Second

// pamAuthFunc runs a PAM authentication and returns its combined output and
// error. runPamtester is the real implementation; tests inject a fake.
type pamAuthFunc func(ctx context.Context, service, user string) ([]byte, error)

func runPamtester(ctx context.Context, service, user string) ([]byte, error) {
	return exec.CommandContext(ctx, "pamtester", service, user, "authenticate").CombinedOutput()
}

// HowdyClient implements both virtual-fido client hooks:
//   - ClientRequestApprover: every WebAuthn ceremony is gated on a live Howdy
//     face match (this is the user-verification step).
//   - ClientDataSaver: the encrypted credential vault, persisted to a file. The
//     vault key is sealed to the TPM when one is present (see tpm_linux.go),
//     otherwise derived from a disk passphrase.
type HowdyClient struct {
	pamService string // e.g. "howdy-only"
	user       string // unix user whose face is enrolled
	vaultPath  string
	passphrase string

	// pamAuth performs the PAM check. Nil means use runPamtester (production);
	// tests override it to exercise the fail-closed logic without a camera.
	pamAuth pamAuthFunc
}

// verify runs the Howdy PAM stack and returns true ONLY on a clean success.
// Every other outcome - non-zero exit, missing binary, timeout, any error -
// returns false. Fail closed: we never assert verification we did not perform.
func (c *HowdyClient) verify(reason string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), howdyVerifyTimeout)
	defer cancel()

	authFn := c.pamAuth
	if authFn == nil {
		authFn = runPamtester
	}

	fmt.Fprintf(os.Stderr, "[howdy] face verification required: %s\n", reason)
	out, err := authFn(ctx, c.pamService, c.user)
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(os.Stderr, "[howdy] DENIED (timeout after %s)\n", howdyVerifyTimeout)
		return false
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[howdy] DENIED: %s (%s)\n", err, trim(out))
		return false
	}
	fmt.Fprintf(os.Stderr, "[howdy] APPROVED (%s)\n", trim(out))
	return true
}

func trim(b []byte) string {
	s := string(b)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// ApproveClientAction gates all four ceremony types on Howdy.
func (c *HowdyClient) ApproveClientAction(action fido_client.ClientAction, params fido_client.ClientActionRequestParams) bool {
	var reason string
	switch action {
	case fido_client.ClientActionFIDOMakeCredential:
		reason = fmt.Sprintf("create passkey for %q", params.RelyingParty)
	case fido_client.ClientActionFIDOGetAssertion:
		reason = fmt.Sprintf("sign in to %q as %q", params.RelyingParty, params.UserName)
	case fido_client.ClientActionU2FRegister:
		reason = "register U2F key"
	case fido_client.ClientActionU2FAuthenticate:
		reason = "authenticate U2F key"
	default:
		fmt.Fprintf(os.Stderr, "[howdy] DENIED: unknown action %d\n", action)
		return false
	}
	return c.verify(reason)
}

// --- ClientDataSaver: encrypted vault persistence ---

func (c *HowdyClient) SaveData(data []byte) {
	// 0600: the vault is encrypted, but never world-readable regardless.
	if err := os.WriteFile(c.vaultPath, data, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "[vault] ERROR writing %s: %s\n", c.vaultPath, err)
	}
}

func (c *HowdyClient) RetrieveData() []byte {
	f, err := os.Open(c.vaultPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vault] ERROR opening %s: %s\n", c.vaultPath, err)
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[vault] ERROR reading %s: %s\n", c.vaultPath, err)
		return nil
	}
	return data
}

func (c *HowdyClient) Passphrase() string {
	return c.passphrase
}
