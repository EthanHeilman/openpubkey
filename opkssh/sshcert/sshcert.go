// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sshcert

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/opkssh/provider"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

type SshCertSmuggler struct {
	SshCert *ssh.Certificate
}

func New(pkt *pktoken.PKToken, principals []string) (*SshCertSmuggler, error) {

	// TODO: assumes email exists in ID Token,
	// this will break for OPs like Azure that do not have email as a claim
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, err
	}

	pubkeySsh, err := sshPubkeyFromPKT(pkt)
	if err != nil {
		return nil, err
	}
	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, err
	}
	pktB64 := string(util.Base64EncodeForJWT(pktJson))
	sshSmuggler := SshCertSmuggler{
		SshCert: &ssh.Certificate{
			Key:             pubkeySsh,
			CertType:        ssh.UserCert,
			KeyId:           claims.Email,
			ValidPrincipals: principals,
			ValidBefore:     ssh.CertTimeInfinity,
			Permissions: ssh.Permissions{
				Extensions: map[string]string{
					"permit-X11-forwarding":   "",
					"permit-agent-forwarding": "",
					"permit-port-forwarding":  "",
					"permit-pty":              "",
					"permit-user-rc":          "",
					"openpubkey-pkt":          pktB64,
				},
			},
		},
	}
	return &sshSmuggler, nil
}

func NewFromAuthorizedKey(certType string, certB64 string) (*SshCertSmuggler, error) {
	if certPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certType + " " + certB64)); err != nil {
		return nil, err
	} else {
		sshCert, ok := certPubkey.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("parsed SSH authorized_key is not an SSH certificate")
		}
		opkcert := &SshCertSmuggler{
			SshCert: sshCert,
		}
		return opkcert, nil
	}
}

func (s *SshCertSmuggler) SignCert(signerMas ssh.MultiAlgorithmSigner) (*ssh.Certificate, error) {
	if err := s.SshCert.SignCert(rand.Reader, signerMas); err != nil {
		return nil, err
	}
	return s.SshCert, nil
}

func (s *SshCertSmuggler) VerifyCaSig(caPubkey ssh.PublicKey) error {
	certCopy := *(s.SshCert)
	certCopy.Signature = nil
	certBytes := certCopy.Marshal()
	certBytes = certBytes[:len(certBytes)-4] // Drops signature length bytes (see crypto.ssh.certs.go)
	return caPubkey.Verify(certBytes, s.SshCert.Signature)
}

func (s *SshCertSmuggler) GetPKToken() (*pktoken.PKToken, error) {
	pktB64, ok := s.SshCert.Extensions["openpubkey-pkt"]
	if !ok {
		return nil, fmt.Errorf("cert is missing required openpubkey-pkt extension")
	}
	pktJson, err := util.Base64DecodeForJWT([]byte(pktB64))
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}
	var pkt *pktoken.PKToken
	if err = json.Unmarshal(pktJson, &pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

func (s *SshCertSmuggler) VerifySshPktCert(ctx context.Context, opConfig provider.Config) (*pktoken.PKToken, error) {
	pkt, err := s.GetPKToken()
	if err != nil {
		return nil, fmt.Errorf("openpubkey-pkt extension in cert failed deserialization: %w", err)
	}

	err = verifyPKToken(ctx, opConfig, pkt)
	if err != nil {
		return nil, err
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()

	cryptoCertKey := (s.SshCert.Key.(ssh.CryptoPublicKey)).CryptoPublicKey()
	jwkCertKey, err := jwk.FromRaw(cryptoCertKey)
	if err != nil {
		return nil, err
	}

	if jwk.Equal(jwkCertKey, upk) {
		return pkt, nil
	} else {
		return nil, fmt.Errorf("public key 'upk' in PK Token does not match public key in certificate")
	}
}

func verifyPKToken(ctx context.Context, opConfig provider.Config, pkt *pktoken.PKToken) error {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctxWithTimeout, opConfig.Issuer())
	if err != nil {
		return err
	}

	idt, err := pkt.Compact()
	if err != nil {
		return err
	}

	// Verify ID token
	verifier := provider.Verifier(&oidc.Config{
		ClientID:        opConfig.ClientID(),
		SkipExpiryCheck: true,
	})
	idToken, err := verifier.Verify(ctx, string(idt))
	if err != nil {
		return err
	}

	// If the id token is expired, verify against the refreshed id token
	if time.Now().After(idToken.Expiry) {
		token, ok := pkt.Op.PublicHeaders().Get("refreshed_id_token")
		if !ok {
			return fmt.Errorf("ID token is expired and no refresh token found")
		}

		refreshedIdToken, ok := token.(string)
		if !ok {
			return fmt.Errorf("failed to cast refreshed_id_token to string")
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: opConfig.ClientID()})
		if _, err = verifier.Verify(ctx, refreshedIdToken); err != nil {
			return err
		}
	}

	// TODO: Use a provider verifier to verify the PK Token
	// err = pkt.VerifyCicSig()
	// if err != nil {
	// 	return fmt.Errorf("error verifying CIC signature on PK Token: %w", err)
	// }

	// Check our nonce matches expected
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return err
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}

	commitment, err := cic.Hash()
	if err != nil {
		return err
	}

	if string(commitment) != claims.Nonce {
		return fmt.Errorf("nonce claim doesn't match, got %q, expected %q", claims.Nonce, string(commitment))
	}

	return nil
}

func sshPubkeyFromPKT(pkt *pktoken.PKToken) (ssh.PublicKey, error) {
	cic, err := pkt.GetCicValues()
	if err != nil {
		return nil, err
	}
	upk := cic.PublicKey()

	var rawkey any
	if err := upk.Raw(&rawkey); err != nil {
		return nil, err
	}
	return ssh.NewPublicKey(rawkey)
}
