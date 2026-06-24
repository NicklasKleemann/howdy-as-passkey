// Command howdy-bridge attaches a virtual FIDO2/CTAP2 authenticator whose
// user-verification step is a live Howdy face match. To the browser it looks
// like an ordinary roaming security key; every create/get ceremony requires
// your face.
//
// The vault that holds passkey private keys is encrypted at rest. The key is
// auto-detected: if a TPM-sealed key exists it is unsealed from this machine's
// TPM, otherwise a passphrase (env/flag) is used for plain disk encryption.
// Run once with --tpm-init to set up (and migrate to) TPM sealing.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	virtual_fido "github.com/bulwarkid/virtual-fido"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
)

func main() {
	defaultUser := ""
	if u, err := user.Current(); err == nil {
		defaultUser = u.Username
	}
	defaultVault := filepath.Join(configDir(), "vault.json")

	pamService := flag.String("pam-service", "howdy-only", "PAM service that runs the Howdy face-only stack")
	unixUser := flag.String("user", defaultUser, "unix user whose Howdy face is enrolled")
	vaultPath := flag.String("vault", defaultVault, "path to the encrypted credential vault")
	passphrase := flag.String("passphrase", "", "vault passphrase; prefer the HOWDY_BRIDGE_PASSPHRASE env var so it is not visible in the process list. Ignored once TPM sealing is set up.")
	tpmInit := flag.Bool("tpm-init", false, "set up TPM sealing: generate a strong key, seal it to this machine's TPM, and migrate the existing vault to it (pass the current --passphrase to migrate)")
	verbose := flag.Bool("verbose", false, "trace-level logging")
	flag.Parse()

	// env var beats the flag so the secret stays out of `ps` / shell history.
	pass := *passphrase
	if pass == "" {
		pass = os.Getenv("HOWDY_BRIDGE_PASSPHRASE")
	}

	if err := os.MkdirAll(filepath.Dir(*vaultPath), 0o700); err != nil {
		fail(fmt.Sprintf("could not create vault dir: %s", err))
	}

	if *tpmInit {
		if err := runTPMInit(*vaultPath, pass); err != nil {
			fail(fmt.Sprintf("tpm-init: %s", err))
		}
		fmt.Fprintf(os.Stderr, "[tpm-init] done. The vault is now sealed to this machine's TPM.\n")
		fmt.Fprintf(os.Stderr, "[tpm-init] You can delete any HOWDY_BRIDGE_PASSPHRASE / passphrase.env now.\n")
		return
	}

	if *unixUser == "" {
		fail("could not determine unix user; pass --user")
	}

	// Auto-detect: TPM-sealed key if present, else the passphrase for disk mode.
	vaultPass, mode, err := resolveVaultPassphrase(pass)
	if err != nil {
		fail(err.Error())
	}

	virtual_fido.SetLogOutput(os.Stderr)
	if *verbose {
		virtual_fido.SetLogLevel(util.LogLevelTrace)
	} else {
		virtual_fido.SetLogLevel(util.LogLevelDebug)
	}

	client := &HowdyClient{
		pamService: *pamService,
		user:       *unixUser,
		vaultPath:  *vaultPath,
		passphrase: vaultPass,
	}

	// Ephemeral self-signed attestation CA, regenerated each run. Fine for a
	// platform authenticator using packed/self attestation; not an identity.
	caPrivateKey, err := identities.CreateCAPrivateKey()
	checkErr(err, "generate attestation CA key")
	ca, err := identities.CreateSelfSignedCA(caPrivateKey)
	checkErr(err, "generate self-signed attestation CA")

	encryptionKey := sha256.Sum256([]byte(vaultPass))
	fidoClient := fido_client.NewDefaultClient(ca, caPrivateKey, encryptionKey, false, client, client)

	fmt.Fprintf(os.Stderr, "[bridge] starting: user=%s pam=%s vault=%s key=%s\n", *unixUser, *pamService, *vaultPath, mode)
	runServer(fidoClient)
}

func configDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "howdy-passkey-bridge")
	}
	return ".howdy-passkey-bridge"
}

func checkErr(err error, what string) {
	if err != nil {
		fail(fmt.Sprintf("%s: %s", what, err))
	}
}

func fail(msg string) {
	fmt.Fprintf(os.Stderr, "[bridge] FATAL: %s\n", msg)
	os.Exit(1)
}
