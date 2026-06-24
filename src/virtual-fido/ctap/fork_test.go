package ctap

// Tests for the howdy-passkey-bridge fork changes to CTAP handling:
//   - user-verification (UV) flag set on a successful approval (makeCredential
//     and getAssertion) — the change that justified forking;
//   - GetInfo advertises uv + plat (platform authenticator);
//   - HandleMessage returns spec errors instead of panicking on empty/unknown
//     commands.

import (
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

// mockCTAPClient is a minimal functional CTAPClient. NewCredentialSource returns
// a real ECDSA-backed credential so signing/attestation paths actually run.
type mockCTAPClient struct {
	approve bool
	rk      bool
	pin     bool
	cred    *identities.CredentialSource
}

func (m *mockCTAPClient) SupportsResidentKey() bool { return m.rk }
func (m *mockCTAPClient) SupportsPIN() bool         { return m.pin }
func (m *mockCTAPClient) NewCredentialSource(_ []webauthn.PublicKeyCredentialParams, _ []webauthn.PublicKeyCredentialDescriptor, _ *webauthn.PublicKeyCredentialRPEntity, _ *webauthn.PublicKeyCrendentialUserEntity) *identities.CredentialSource {
	return m.cred
}
func (m *mockCTAPClient) GetAssertionSource(_ string, _ []webauthn.PublicKeyCredentialDescriptor) *identities.CredentialSource {
	return m.cred
}
func (m *mockCTAPClient) CreateAttestationCertificiate(_ *cose.SupportedCOSEPrivateKey) []byte {
	return []byte{0x30, 0x03, 0x01, 0x02, 0x03} // opaque cert bytes; not validated here
}
func (m *mockCTAPClient) PINHash() []byte                  { return nil }
func (m *mockCTAPClient) SetPINHash([]byte)                {}
func (m *mockCTAPClient) PINRetries() int32                { return 0 }
func (m *mockCTAPClient) SetPINRetries(int32)              {}
func (m *mockCTAPClient) PINKeyAgreement() *crypto.ECDHKey { return nil }
func (m *mockCTAPClient) PINToken() []byte                 { return nil }
func (m *mockCTAPClient) ApproveAccountCreation(string) bool {
	return m.approve
}
func (m *mockCTAPClient) ApproveAccountLogin(*identities.CredentialSource) bool {
	return m.approve
}

func testRPandUser() (*webauthn.PublicKeyCredentialRPEntity, *webauthn.PublicKeyCrendentialUserEntity) {
	rp := &webauthn.PublicKeyCredentialRPEntity{ID: "example.com", Name: "Example"}
	user := &webauthn.PublicKeyCrendentialUserEntity{ID: []byte{1, 2, 3, 4}, Name: "user", DisplayName: "User"}
	return rp, user
}

func newServerWithCred(approve bool) *CTAPServer {
	rp, user := testRPandUser()
	cred := identities.NewIdentityVault().NewIdentity(rp, user)
	return NewCTAPServer(&mockCTAPClient{approve: approve, rk: true, cred: cred})
}

// --- the core fork fix: UV flag on a verified ceremony ---

func TestMakeCredentialSetsUVFlag(t *testing.T) {
	server := newServerWithCred(true)
	rp, user := testRPandUser()
	args := makeCredentialArgs{
		ClientDataHash:   make([]byte, 32),
		RP:               rp,
		User:             user,
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256}},
	}
	data := append([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(args)...)
	resp := server.HandleMessage(data)

	if resp[0] != byte(ctap1ErrSuccess) {
		t.Fatalf("status = 0x%02x, want success", resp[0])
	}
	var mcr makeCredentialResponse
	if err := cbor.Unmarshal(resp[1:], &mcr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	flags := mcr.AuthData[32]
	if flags&flagUP == 0 {
		t.Error("UP not set")
	}
	if flags&flagUV == 0 {
		t.Errorf("UV not set (flags=0x%02x) — the fork fix regressed", flags)
	}
	if flags&flagAT == 0 {
		t.Error("attested-credential-data bit not set")
	}
}

func TestMakeCredentialDeniedWhenApproverRejects(t *testing.T) {
	server := newServerWithCred(false)
	rp, user := testRPandUser()
	args := makeCredentialArgs{
		ClientDataHash:   make([]byte, 32),
		RP:               rp,
		User:             user,
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256}},
	}
	data := append([]byte{byte(ctapCommandMakeCredential)}, util.MarshalCBOR(args)...)
	resp := server.HandleMessage(data)
	if resp[0] != byte(ctap2ErrOperationDenied) {
		t.Fatalf("status = 0x%02x, want OperationDenied (0x27)", resp[0])
	}
}

func TestGetAssertionSetsUVFlag(t *testing.T) {
	server := newServerWithCred(true)
	args := getAssertionArgs{RPID: "example.com", ClientDataHash: make([]byte, 32)}
	data := append([]byte{byte(ctapCommandGetAssertion)}, util.MarshalCBOR(args)...)
	resp := server.HandleMessage(data)

	if resp[0] != byte(ctap1ErrSuccess) {
		t.Fatalf("status = 0x%02x, want success", resp[0])
	}
	var gar getAssertionResponse
	if err := cbor.Unmarshal(resp[1:], &gar); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	flags := gar.AuthenticatorData[32]
	if flags&flagUP == 0 || flags&flagUV == 0 {
		t.Errorf("expected UP+UV set, flags=0x%02x", flags)
	}
}

// --- GetInfo advertises uv + plat ---

func TestGetInfoAdvertisesUVandPlatform(t *testing.T) {
	server := newServerWithCred(true)
	resp := server.HandleMessage([]byte{byte(ctapCommandGetInfo)})
	if resp[0] != byte(ctap1ErrSuccess) {
		t.Fatalf("status = 0x%02x, want success", resp[0])
	}
	var info getInfoResponse
	if err := cbor.Unmarshal(resp[1:], &info); err != nil {
		t.Fatalf("decode getInfo: %v", err)
	}
	if !info.Options.CanUserVerification {
		t.Error("uv not advertised in GetInfo")
	}
	if !info.Options.IsPlatform {
		t.Error("plat (platform authenticator) not advertised in GetInfo")
	}
	if !info.Options.CanResidentKey {
		t.Error("rk not advertised though client supports resident keys")
	}
}

// --- robustness: no panic on empty/unknown commands ---

func TestHandleMessageEmptyReturnsError(t *testing.T) {
	server := newServerWithCred(true)
	resp := server.HandleMessage([]byte{})
	if len(resp) != 1 || resp[0] != byte(ctap1ErrInvalidLength) {
		t.Fatalf("empty message: got %v, want [InvalidLength]", resp)
	}
}

func TestHandleMessageUnknownCommandReturnsError(t *testing.T) {
	server := newServerWithCred(true)
	// 0x40 is the probe that crashed the daemon before the fix.
	resp := server.HandleMessage([]byte{0x40, 0xa2, 0x01})
	if len(resp) != 1 || resp[0] != byte(ctap1ErrInvalidCommand) {
		t.Fatalf("unknown command: got %v, want [InvalidCommand]", resp)
	}
}
