// Command howdy-bridge attaches a virtual FIDO2/CTAP2 authenticator whose
// user-verification step is a live Howdy face match. To the browser it looks
// like an ordinary roaming security key; every create/get ceremony requires
// your face.
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
	passphrase := flag.String("passphrase", "", "vault passphrase (REQUIRED until TPM sealing lands)")
	verbose := flag.Bool("verbose", false, "trace-level logging")
	flag.Parse()

	if *unixUser == "" {
		fail("could not determine unix user; pass --user")
	}
	if *passphrase == "" {
		fail("--passphrase is required (the vault is encrypted at rest; TPM sealing will replace this)")
	}

	virtual_fido.SetLogOutput(os.Stderr)
	if *verbose {
		virtual_fido.SetLogLevel(util.LogLevelTrace)
	} else {
		virtual_fido.SetLogLevel(util.LogLevelDebug)
	}

	if err := os.MkdirAll(filepath.Dir(*vaultPath), 0o700); err != nil {
		fail(fmt.Sprintf("could not create vault dir: %s", err))
	}

	client := &HowdyClient{
		pamService: *pamService,
		user:       *unixUser,
		vaultPath:  *vaultPath,
		passphrase: *passphrase,
	}

	// Ephemeral self-signed attestation CA, regenerated each run. Fine for a
	// platform authenticator using packed/self attestation; not an identity.
	caPrivateKey, err := identities.CreateCAPrivateKey()
	checkErr(err, "generate attestation CA key")
	ca, err := identities.CreateSelfSignedCA(caPrivateKey)
	checkErr(err, "generate self-signed attestation CA")

	// The vault-at-rest key. Derived from the passphrase for now; a later step
	// seals this to the TPM so the vault only decrypts with chip + face.
	encryptionKey := sha256.Sum256([]byte(*passphrase))

	fidoClient := fido_client.NewDefaultClient(ca, caPrivateKey, encryptionKey, false, client, client)

	fmt.Fprintf(os.Stderr, "[bridge] starting: user=%s pam=%s vault=%s\n", *unixUser, *pamService, *vaultPath)
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
