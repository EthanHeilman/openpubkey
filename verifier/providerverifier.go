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

package verifier

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/client/providers/discover"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type DefaultProviderVerifier struct {
	issuer          string
	commitmentClaim string
	options         ProviderVerifierOpts
}

type ProviderVerifierOpts struct {
	// If ClientID is specified, then verification will require that the ClientID
	// be present in the audience ("aud") claim of the PK token payload
	ClientID string
	// Specifies whether to skip the Client ID check, defaults to false
	SkipClientIDCheck bool
	// Custom function for discovering public key of Provider
	DiscoverPublicKey *discover.PublicKeyFinder
	// Allows for successful verification of expired tokens
	SkipExpirationCheck bool
	// Only allows GQ signatures, a provider signature under any other algorithm
	// is seen as an error
	GQOnly bool
}

// Creates a new ProviderVerifier with required fields
//
// issuer: Is the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
// commitmentClaim: the ID token payload claim name where the cicHash was stored during issuance
func NewProviderVerifier(issuer, commitmentClaim string, options ProviderVerifierOpts) *DefaultProviderVerifier {
	v := &DefaultProviderVerifier{
		issuer:          issuer,
		commitmentClaim: commitmentClaim,
		options:         options,
	}

	// If no custom DiscoverPublicKey function is set, set default
	if v.options.DiscoverPublicKey == nil {
		v.options.DiscoverPublicKey = discover.DefaultPubkeyFinder()
	}

	return v
}

func (v *DefaultProviderVerifier) Issuer() string {
	return v.issuer
}

func (v *DefaultProviderVerifier) VerifyProvider(ctx context.Context, pkt *pktoken.PKToken) error {
	// Check whether Audience claim matches provided Client ID
	// No error is thrown if option is set to skip client ID check
	if err := verifyAudience(pkt, v.options.ClientID); err != nil && !v.options.SkipClientIDCheck {
		return err
	}

	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("provider algorithm type missing")
	}

	if alg != gq.GQ256 && v.options.GQOnly {
		return ErrNonGQUnsupported
	}

	switch alg {
	case gq.GQ256:
		if err := v.verifyGQSig(ctx, pkt); err != nil {
			return fmt.Errorf("error verifying OP GQ signature on PK Token: %w", err)
		}
	case jwa.RS256:
		pubKeyRecord, err := v.providerPublicKey(ctx, pkt)
		if err != nil {
			return fmt.Errorf("failed to get OP public key: %w", err)
		}

		if _, err := jws.Verify(pkt.OpToken, jws.WithKey(alg, pubKeyRecord.PublicKey)); err != nil {
			return err
		}
	}

	if err := v.verifyCommitment(pkt); err != nil {
		return err
	}

	return nil
}

// This function takes in an OIDC Provider created ID token or GQ-signed modification of one and returns
// the associated public key
func (v *DefaultProviderVerifier) providerPublicKey(ctx context.Context, pkt *pktoken.PKToken) (*discover.PublicKeyRecord, error) {
	// TODO: We should support verifying by JKT if not kid exists in the header
	// Created issue https://github.com/openpubkey/openpubkey/issues/137 to track this
	return v.options.DiscoverPublicKey.ByToken(ctx, v.Issuer(), pkt.OpToken)
}

func (v *DefaultProviderVerifier) verifyCommitment(pkt *pktoken.PKToken) error {
	var claims map[string]any
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	cic, err := pkt.GetCicValues()
	if err != nil {
		return err
	}
	expectedCommitment, err := cic.Hash()
	if err != nil {
		return err
	}
	commitment, ok := claims[v.commitmentClaim]
	if !ok {
		return fmt.Errorf("missing commitment claim %s", v.commitmentClaim)
	}

	if commitment != string(expectedCommitment) {
		return fmt.Errorf("nonce claim doesn't match, got %q, expected %s", commitment, string(expectedCommitment))
	}
	return nil
}

// verifyGQSig verifies the signature of a PK token with a GQ signature. The
// parameter issuer should be the issuer of the ProviderVerifier not the
// issuer of the PK Token
func (v *DefaultProviderVerifier) verifyGQSig(ctx context.Context, pkt *pktoken.PKToken) error {
	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("missing provider algorithm header")
	}

	if alg != gq.GQ256 {
		return fmt.Errorf("signature is not of type GQ")
	}

	origHeaders, err := originalTokenHeaders(pkt.OpToken)
	if err != nil {
		return fmt.Errorf("malformatted PK token headers: %w", err)
	}

	alg = origHeaders.Algorithm()
	if alg != jwa.RS256 {
		return fmt.Errorf("expected original headers to contain RS256 alg, got %s", alg)
	}

	pktIssuer, err := pkt.Issuer()
	if err != nil {
		return fmt.Errorf("missing issuer: %w", err)
	}
	if pktIssuer != v.issuer {
		return fmt.Errorf("issuer of PK token (%s) doesn't match expected issuer (%s)", pktIssuer, v.issuer)
	}

	publicKeyRecord, err := v.options.DiscoverPublicKey.ByToken(ctx, v.Issuer(), pkt.OpToken)
	if err != nil {
		return fmt.Errorf("failed to get provider public key: %w", err)
	}

	rsaKey, ok := publicKeyRecord.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("jwk is not an RSA key")
	}
	ok, err = gq.GQ256VerifyJWT(rsaKey, pkt.OpToken)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("error verifying OP GQ signature on PK Token (ID Token invalid)")
	}
	return nil
}

func originalTokenHeaders(token []byte) (jws.Headers, error) {
	origHeadersB64, err := gq.OriginalJWTHeaders(token)
	if err != nil {
		return nil, fmt.Errorf("malformatted PK token headers: %w", err)
	}

	origHeaders, err := util.Base64DecodeForJWT(origHeadersB64)
	if err != nil {
		return nil, fmt.Errorf("error decoding original token headers: %w", err)
	}

	headers := jws.NewHeaders()
	err = json.Unmarshal(origHeaders, &headers)
	if err != nil {
		return nil, fmt.Errorf("error parsing segment: %w", err)
	}

	return headers, nil
}

func verifyAudience(pkt *pktoken.PKToken, clientID string) error {
	var claims struct {
		Audience any `json:"aud"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	switch aud := claims.Audience.(type) {
	case string:
		if aud != clientID {
			return fmt.Errorf("audience does not contain clientID %s, aud = %s", clientID, aud)
		}
	case []any:
		for _, audience := range aud {
			if audience.(string) == clientID {
				return nil
			}
		}
		return fmt.Errorf("audience does not contain clientID %s, aud = %v", clientID, aud)
	default:
		return fmt.Errorf("missing audience claim")
	}
	return nil
}
