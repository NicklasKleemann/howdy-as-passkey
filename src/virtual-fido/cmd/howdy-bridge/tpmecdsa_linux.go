//go:build linux

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
)

// In-chip ECDSA: generate a P-256 signing key inside the TPM and sign with it,
// so the private key never leaves the chip. This is the building block for
// TPM-backed passkeys (phase 1: prove the crypto before the library plumbing).

func eccSignTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{
					HashAlg: tpm2.TPMAlgSHA256,
				}),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
	}
}

// tpmCreateECDSAKey creates a P-256 signing key in the TPM under the owner SRK.
// It returns a self-contained blob (public+private) and the public key.
func tpmCreateECDSAKey() (blob []byte, pub *ecdsa.PublicKey, err error) {
	t, err := openTPM()
	if err != nil {
		return nil, nil, err
	}
	defer t.Close()

	primary, err := primaryHandle(t)
	if err != nil {
		return nil, nil, fmt.Errorf("create primary: %w", err)
	}
	defer flush(t, primary.ObjectHandle)

	created, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{Handle: primary.ObjectHandle, Name: primary.Name, Auth: tpm2.PasswordAuth(nil)},
		InPublic:     tpm2.New2B(eccSignTemplate()),
	}.Execute(t)
	if err != nil {
		return nil, nil, fmt.Errorf("create ecdsa key: %w", err)
	}

	pub, err = eccPublicFromTPM2B(created.OutPublic)
	if err != nil {
		return nil, nil, err
	}
	return marshalSealed(created.OutPublic, created.OutPrivate), pub, nil
}

// tpmECDSASign loads the key blob and signs the digest inside the TPM, returning
// an ASN.1 DER ECDSA signature (the form WebAuthn/x509 expect).
func tpmECDSASign(blob, digest []byte) ([]byte, error) {
	pub2b, priv, err := unmarshalSealed(blob)
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
		InPublic:     pub2b,
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	defer flush(t, loaded.ObjectHandle)

	signed, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: tpm2.PasswordAuth(nil)},
		Digest:    tpm2.TPM2BDigest{Buffer: digest},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSchemeHash{
				HashAlg: tpm2.TPMAlgSHA256,
			}),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	ecc, err := signed.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("extract ecdsa signature: %w", err)
	}
	r := new(big.Int).SetBytes(ecc.SignatureR.Buffer)
	s := new(big.Int).SetBytes(ecc.SignatureS.Buffer)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("marshal der signature: %w", err)
	}
	return der, nil
}

func eccPublicFromTPM2B(pub2b tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	pub, err := pub2b.Contents()
	if err != nil {
		return nil, fmt.Errorf("public contents: %w", err)
	}
	eccDetail, err := pub.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("public ecc point: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(eccDetail.X.Buffer),
		Y:     new(big.Int).SetBytes(eccDetail.Y.Buffer),
	}, nil
}
