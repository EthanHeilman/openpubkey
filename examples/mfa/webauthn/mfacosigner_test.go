package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
)

func TestInitAuth(t *testing.T) {

	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	kid := "test-kid"
	cosignerURI := "https://example.com/mfacosigner"
	RPID := "http://localhost"

	cos, err := NewCosigner(signer, alg, cosignerURI, kid, RPID)
	if err != nil {
		t.Error(err)
	}

	email := "arthur.aardvark@example.com"
	pkt, err := mocks.GenerateMockPKTokenWithEmail(signer, alg, email)
	if err != nil {
		t.Fatal(err)
	}

	ruri := "https://example.com/mfaredirect"
	msg := InitMFAAuth{
		RedirectUri: ruri,
		TimeSigned:  time.Now().Unix(),
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := pkt.NewSignedMessage(msgJson, signer)
	authID, err := cos.InitAuth(pkt, sig)
	if err != nil {
		t.Fatal(err)
	}

	authcode, err := cos.NewAuthcode(authID)
	if err != nil {
		t.Fatal(err)
	}

	authcodeSig, err := pkt.NewSignedMessage(authcode, signer)

	pktCosB64, err := cos.CheckAuthcode(authcode, authcodeSig)
	if err != nil {
		t.Fatal(err)
	}

	pktCosJson, err := util.Base64DecodeForJWT(pktCosB64)
	if err != nil {
		t.Fatal(err)
	}

	var pktCos pktoken.PKToken
	err = json.Unmarshal(pktCosJson, &pktCos)
	if err != nil {
		t.Fatal(err)
	}
	if pktCos.Cos == nil {
		t.Fatal("Expected pktCos to be cosigned")
	}
}

func TestFullFlow(t *testing.T) {

	// Step 0: Setup
	// Create our PK Token and signer
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}
	email := "arthur.aardvark@example.com"
	pkt, err := mocks.GenerateMockPKTokenWithEmail(signer, alg, email)
	if err != nil {
		t.Fatal(err)
	}

	// Create our MFA Cosigner
	cosSigner, err := util.GenKeyPair(alg)
	kid := "test-kid"
	cosignerURI := "https://example.com/mfacosigner"
	RPID := "http://localhost"
	cos, err := NewCosigner(cosSigner, alg, cosignerURI, kid, RPID)
	if err != nil {
		t.Error(err)
	}

	// Create our MFA device
	wauthnDevice, err := NewWebauthnDevice(RPID)
	if err != nil {
		t.Error(err)
	}

	// Step 1: Init MFA Cosigner flow
	ruri := "https://example.com/mfaredirect"
	msg := InitMFAAuth{
		RedirectUri: ruri,
		TimeSigned:  time.Now().Unix(),
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := pkt.NewSignedMessage(msgJson, signer)
	authID, err := cos.InitAuth(pkt, sig)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: Register MFA device
	createCreation, err := cos.BeginRegistration(authID)
	if err != nil {
		t.Fatal(err)
	}
	if createCreation == nil {
		t.Fatal("Expected cred creation to not be nil")
	}
	credCreationResp, err := wauthnDevice.RegResp(createCreation)
	if err != nil {
		t.Fatal(err)
	}
	err = cos.FinishRegistration(authID, credCreationResp)
	if err != nil {
		t.Fatal(err)
	}

	// Step 3: Login MFA device
	credAssert, err := cos.BeginLogin(authID)
	if err != nil {
		t.Fatal(err)
	}
	loginResp, err := wauthnDevice.LoginResp(credAssert)
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	authcodeRet, ruriRet, err := cos.FinishLogin(authID, loginResp)
	if err != nil {
		t.Fatal(err)
	}
	if credAssert == nil {
		t.Fatal("Expected cred creation to not be nil")
	}
	if ruriRet == nil {
		t.Fatal("Expected ruri to not be nil")
	}

	authcodeSig, err := pkt.NewSignedMessage(authcodeRet, signer)

	pktCosB64, err := cos.CheckAuthcode(authcodeRet, authcodeSig)
	if err != nil {
		t.Fatal(err)
	}

	pktCosJson, err := util.Base64DecodeForJWT(pktCosB64)
	if err != nil {
		t.Fatal(err)
	}

	var pktCos pktoken.PKToken
	err = json.Unmarshal(pktCosJson, &pktCos)
	if err != nil {
		t.Fatal(err)
	}
	if pktCos.Cos == nil {
		t.Fatal("Expected pktCos to be cosigned")
	}
}

// For testing purposes we create a WebAuthn device to run the client part of the protocol
type WebAuthnDevice struct {
	signer     crypto.Signer
	PubkeyCbor []byte
	RpID       string
	RpIDHash   []byte
}

func NewWebauthnDevice(rpID string) (*WebAuthnDevice, error) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	pubkey := signer.Public().(*ecdsa.PublicKey)
	pubkeyCbor := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.AlgES256),
		XCoord: pubkey.X.Bytes(),
		YCoord: pubkey.Y.Bytes(),
	}
	pubkeyCborBytes, err := webauthncbor.Marshal(pubkeyCbor)
	if err != nil {
		return nil, err
	}

	rpIDHash := sha256.Sum256([]byte(rpID))

	return &WebAuthnDevice{
		signer:     signer,
		PubkeyCbor: pubkeyCborBytes,
		RpID:       rpID,
		RpIDHash:   rpIDHash[:],
	}, nil
}

func (wa *WebAuthnDevice) RegResp(createCreation *protocol.CredentialCreation) (*protocol.ParsedCredentialCreationData, error) {
	return &protocol.ParsedCredentialCreationData{
		ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
			ParsedCredential: protocol.ParsedCredential{
				ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
				Type: "public-key",
			},
			RawID: []byte{1, 1, 1, 1, 1},
			ClientExtensionResults: protocol.AuthenticationExtensionsClientOutputs{
				"appid": true,
			},
			AuthenticatorAttachment: "platform",
		},
		Response: protocol.ParsedAttestationResponse{
			CollectedClientData: protocol.CollectedClientData{
				Type:      protocol.CeremonyType("webauthn.create"),
				Challenge: createCreation.Response.Challenge.String(),
				Origin:    createCreation.Response.RelyingParty.ID,
			},
			AttestationObject: protocol.AttestationObject{
				Format:      "none",
				RawAuthData: []byte{1, 1, 1, 1, 1},
				AuthData: protocol.AuthenticatorData{
					RPIDHash: wa.RpIDHash,
					Counter:  0,
					Flags:    0x041,
					AttData: protocol.AttestedCredentialData{
						AAGUID:              make([]byte, 16),
						CredentialID:        []byte{5, 1, 1, 1, 1},
						CredentialPublicKey: wa.PubkeyCbor,
					},
				},
			},
			Transports: []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC, "fake"},
		},
	}, nil
}

func (wa *WebAuthnDevice) LoginResp(credAssert *protocol.CredentialAssertion) (*protocol.ParsedCredentialAssertionData, error) {
	loginRespData := &protocol.ParsedCredentialAssertionData{
		ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
			ParsedCredential: protocol.ParsedCredential{
				ID:   "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
				Type: "public-key",
			},
			RawID: []byte{5, 1, 1, 1, 1},
			ClientExtensionResults: map[string]interface{}{
				"appID": "example.com",
			},
		},
		Response: protocol.ParsedAssertionResponse{
			CollectedClientData: protocol.CollectedClientData{
				Type:      protocol.CeremonyType("webauthn.get"),
				Challenge: credAssert.Response.Challenge.String(),
				Origin:    wa.RpID,
				Hint:      "do not compare clientDataJSON against a template. See https://goo.gl/yabPex",
			},
			AuthenticatorData: protocol.AuthenticatorData{
				RPIDHash: wa.RpIDHash,
				Counter:  1553097241,
				Flags:    0x045,
				AttData: protocol.AttestedCredentialData{
					AAGUID:              []byte{1, 1, 1, 1, 3},
					CredentialID:        []byte{1, 1, 1, 1, 4},
					CredentialPublicKey: []byte{1, 1, 1, 1, 5},
				},
			},
			Signature:  []byte{1, 1, 1, 1, 6},
			UserHandle: []byte("1234567890"), // ID Token sub
		},
		Raw: protocol.CredentialAssertionResponse{
			PublicKeyCredential: protocol.PublicKeyCredential{
				Credential: protocol.Credential{
					Type: "public-key",
					ID:   "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
				},
				RawID: []byte{5, 1, 1, 1, 1},
				ClientExtensionResults: map[string]interface{}{
					"appID": "example.com",
				},
			},
		},
	}

	return wa.SignLoginChallenge(loginRespData)
}

func (wa *WebAuthnDevice) SignLoginChallenge(loginRespData *protocol.ParsedCredentialAssertionData) (*protocol.ParsedCredentialAssertionData, error) {
	clientDataHash := sha256.Sum256(loginRespData.Raw.AssertionResponse.ClientDataJSON)
	sigData := append(loginRespData.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)
	sigHash := sha256.Sum256(sigData)
	sigWebauthn, err := wa.signer.Sign(rand.Reader, sigHash[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	loginRespData.Response.Signature = sigWebauthn

	return loginRespData, nil
}
