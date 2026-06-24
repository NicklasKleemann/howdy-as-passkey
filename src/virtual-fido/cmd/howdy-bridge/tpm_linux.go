//go:build linux

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// vaultKeyPath is where the TPM-sealed vault key lives. Its presence is what
// switches the bridge from disk-passphrase mode to TPM mode.
func vaultKeyPath() string {
	return filepath.Join(configDir(), "vault.key.tpm")
}

// resolveVaultPassphrase auto-detects the key source:
//   - if a TPM-sealed key exists, unseal it from this machine's TPM ("tpm");
//   - otherwise use the provided fallback passphrase for disk encryption ("disk").
func resolveVaultPassphrase(fallback string) (pass string, mode string, err error) {
	kp := vaultKeyPath()
	if _, statErr := os.Stat(kp); statErr == nil {
		blob, e := os.ReadFile(kp)
		if e != nil {
			return "", "", fmt.Errorf("read sealed key %s: %w", kp, e)
		}
		secret, e := tpmUnseal(blob)
		if e != nil {
			return "", "", fmt.Errorf("unseal vault key from TPM (sealed to a different TPM, or no 'tss' group access?): %w", e)
		}
		return string(secret), "tpm", nil
	}
	if fallback == "" {
		return "", "", fmt.Errorf("no TPM-sealed key at %s and no passphrase set (HOWDY_BRIDGE_PASSPHRASE / --passphrase); run with --tpm-init to enable TPM sealing", kp)
	}
	return fallback, "disk", nil
}

// runTPMInit sets up TPM sealing. It generates a strong random passphrase, seals
// it to the TPM, and (if a vault already exists) migrates that vault from its
// current passphrase to the new sealed one. Ordering is chosen so a failure
// never leaves the vault unreadable: the current vault is verified-decryptable
// and backed up first, the key is sealed and verify-unsealed before it is
// trusted, and the re-encrypted vault is written atomically.
func runTPMInit(vaultPath, currentPass string) error {
	kp := vaultKeyPath()
	if _, e := os.Stat(kp); e == nil {
		return fmt.Errorf("a sealed key already exists at %s; remove it first if you really want to re-init", kp)
	}

	vaultData, readErr := os.ReadFile(vaultPath)
	hasVault := readErr == nil && len(vaultData) > 0

	// Verify we can read the existing vault BEFORE changing anything.
	var state *identities.FIDODeviceConfig
	if hasVault {
		if currentPass == "" {
			return fmt.Errorf("existing vault at %s needs migrating; pass its current --passphrase (or HOWDY_BRIDGE_PASSPHRASE)", vaultPath)
		}
		s, e := identities.DecryptFIDOState(vaultData, currentPass)
		if e != nil {
			return fmt.Errorf("cannot decrypt existing vault with the given passphrase: %w", e)
		}
		state = s
	}

	// Strong random passphrase, sealed and verified before we rely on it.
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return fmt.Errorf("generate key: %w", e)
	}
	newPass := base64.RawStdEncoding.EncodeToString(raw)

	blob, e := tpmSeal([]byte(newPass))
	if e != nil {
		return fmt.Errorf("TPM seal: %w", e)
	}
	if got, e := tpmUnseal(blob); e != nil || string(got) != newPass {
		return fmt.Errorf("sealed key failed verify-unseal, refusing to proceed: %v", e)
	}

	// Back up the current vault before touching it.
	if hasVault {
		bak := vaultPath + ".pre-tpm.bak"
		if e := os.WriteFile(bak, vaultData, 0o600); e != nil {
			return fmt.Errorf("write vault backup %s: %w", bak, e)
		}
		fmt.Fprintf(os.Stderr, "[tpm-init] backed up vault to %s\n", bak)
	}

	// Persist the sealed key first so the new passphrase is always recoverable.
	if e := writeFileAtomic(kp, blob, 0o600); e != nil {
		return fmt.Errorf("write sealed key %s: %w", kp, e)
	}

	// Re-encrypt the vault with the new passphrase.
	if hasVault {
		reenc, e := identities.EncryptFIDOState(*state, newPass)
		if e != nil {
			return fmt.Errorf("re-encrypt vault: %w", e)
		}
		if e := writeFileAtomic(vaultPath, reenc, 0o600); e != nil {
			return fmt.Errorf("write re-keyed vault: %w", e)
		}
		fmt.Fprintf(os.Stderr, "[tpm-init] migrated vault to the TPM-sealed key\n")
	}
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TPM seal-at-rest. The vault is encrypted with a high-entropy passphrase; that
// passphrase is sealed to this machine's TPM under a primary key in the owner
// hierarchy. The sealed blob on disk is useless without this exact TPM, so the
// vault cannot be decrypted on another machine and the passphrase never lives
// in plaintext.

const tpmDevicePath = "/dev/tpmrm0"

func openTPM() (transport.TPMCloser, error) {
	t, err := linuxtpm.Open(tpmDevicePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tpmDevicePath, err)
	}
	return t, nil
}

// primaryHandle creates the deterministic owner-hierarchy primary used as the
// parent for the sealed object. Same template + same TPM owner seed gives the
// same key every boot, so we never need to persist it.
func primaryHandle(t transport.TPM) (*tpm2.CreatePrimaryResponse, error) {
	return tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
}

func flush(t transport.TPM, h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(t)
}

// sealTemplate is a plain sealed-data object (keyedhash, no scheme): it just
// stores bytes, bound to this TPM and parent.
func sealTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
	}
}

// tpmSeal seals secret and returns a self-contained blob (public + private).
func tpmSeal(secret []byte) ([]byte, error) {
	t, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer t.Close()

	primary, err := primaryHandle(t)
	if err != nil {
		return nil, fmt.Errorf("create primary: %w", err)
	}
	defer flush(t, primary.ObjectHandle)

	created, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: secret}),
			},
		},
		InPublic: tpm2.New2B(sealTemplate()),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return marshalSealed(created.OutPublic, created.OutPrivate), nil
}

// tpmUnseal recovers the secret from a blob produced by tpmSeal on this TPM.
func tpmUnseal(blob []byte) ([]byte, error) {
	pub, priv, err := unmarshalSealed(blob)
	if err != nil {
		return nil, err
	}
	t, err := openTPM()
	if err != nil {
		return nil, err
	}
	defer t.Close()

	primary, err := primaryHandle(t)
	if err != nil {
		return nil, fmt.Errorf("create primary: %w", err)
	}
	defer flush(t, primary.ObjectHandle)

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    priv,
		InPublic:     pub,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("load sealed object: %w", err)
	}
	defer flush(t, loaded.ObjectHandle)

	unsealed, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: tpm2.PasswordAuth(nil)},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	return unsealed.OutData.Buffer, nil
}

// blob format: u32 len(public) | public | u32 len(private) | private
func marshalSealed(pub tpm2.TPM2BPublic, priv tpm2.TPM2BPrivate) []byte {
	pb := tpm2.Marshal(pub)
	rb := tpm2.Marshal(priv)
	out := make([]byte, 0, 8+len(pb)+len(rb))
	out = binary.BigEndian.AppendUint32(out, uint32(len(pb)))
	out = append(out, pb...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(rb)))
	out = append(out, rb...)
	return out
}

func unmarshalSealed(blob []byte) (tpm2.TPM2BPublic, tpm2.TPM2BPrivate, error) {
	var pub tpm2.TPM2BPublic
	var priv tpm2.TPM2BPrivate
	if len(blob) < 8 {
		return pub, priv, fmt.Errorf("sealed blob too short")
	}
	n := binary.BigEndian.Uint32(blob[:4])
	rest := blob[4:]
	if uint32(len(rest)) < n {
		return pub, priv, fmt.Errorf("sealed blob truncated (public)")
	}
	pubP, err := tpm2.Unmarshal[tpm2.TPM2BPublic](rest[:n])
	if err != nil {
		return pub, priv, fmt.Errorf("unmarshal public: %w", err)
	}
	rest = rest[n:]
	if len(rest) < 4 {
		return pub, priv, fmt.Errorf("sealed blob truncated (len)")
	}
	m := binary.BigEndian.Uint32(rest[:4])
	rest = rest[4:]
	if uint32(len(rest)) < m {
		return pub, priv, fmt.Errorf("sealed blob truncated (private)")
	}
	privP, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](rest[:m])
	if err != nil {
		return pub, priv, fmt.Errorf("unmarshal private: %w", err)
	}
	return *pubP, *privP, nil
}
