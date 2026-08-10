// Copyright 2025 OpenPubkey
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

package providers

import (
	"context"
	"crypto"
	"fmt"

	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// KeyBindingOp configures standardOp to use the OIDC key binding protocol as described in the
// draft standard "OpenID Connect Key Binding" at https://openid.github.io/connect-key-binding/main.html
type KeyBindingOp struct {
	StandardOp
}

// ConfigKeyBinding sets up the KeyBindingOp to use the provided signer and algorithm.
// This is required to successfully use this type of OP.
//
// The signer is handed to zitadel/oidc's native key binding support
// (rp.WithKeyBinding), which appends the bound_key scope, sends dpop_jkt on the
// authorization request, signs a DPoP proof for every token request, and
// verifies that the returned ID Token is actually bound to the key. See
// (*StandardOp).keyBindingOptions.
func (s *KeyBindingOp) ConfigKeyBinding(kbSigner crypto.Signer, kbAlg string) error {
	if kbSigner == nil {
		return fmt.Errorf("key binding signer must not be nil")
	}
	s.keyBindingSigner = kbSigner
	s.keyBindingSignerAlg = kbAlg
	return nil
}

func (s *KeyBindingOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(
		s.issuer,
		ProviderVerifierOpts{
			CommitType:        CommitTypesEnum.KEY_BOUND,
			ClientID:          s.clientID,
			DiscoverPublicKey: &s.publicKeyFinder,
		})
	return vp.VerifyIDToken(ctx, idt, cic)
}

// KeyBindingOpRefreshable extends KeyBindingOp to support a refresh flow
type KeyBindingOpRefreshable struct {
	KeyBindingOp
}

func (r *KeyBindingOpRefreshable) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
	cookieHandler, err := configCookieHandler()
	if err != nil {
		return nil, err
	}
	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(
			rp.WithIssuedAtOffset(r.IssuedAtOffset),
			rp.WithNonce(nil), // disable nonce check
		),
	}
	if r.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(r.HttpClient))
	}
	options = append(options, r.keyBindingOptions()...)

	// The redirect URI is not sent in the refresh request so we set it to an empty string.
	// According to the OIDC spec the only values sent in a refresh request are:
	// client_id, client_secret, grant_type, refresh_token, and scope.
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, r.issuer, r.clientID,
		r.ClientSecret, redirectURI, r.Scopes, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	retTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, string(refreshToken), "", "")
	if err != nil {
		return nil, err
	}

	if retTokens.RefreshToken == "" {
		// Google does not rotate refresh tokens, the one you get at the
		// beginning is the only one you'll ever get. This may not be true
		// of OPs.
		retTokens.RefreshToken = string(refreshToken)
	}

	return &simpleoidc.Tokens{
		IDToken:      []byte(retTokens.IDToken),
		RefreshToken: []byte(retTokens.RefreshToken),
		AccessToken:  []byte(retTokens.AccessToken)}, nil
}

func (r *KeyBindingOpRefreshable) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
	}
	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
	}
	// The key binding is carried in the cnf claim, not in a CIC commitment. So
	// proving the refreshed token is bound to the same key as the original is
	// done by comparing cnf claims (by JWK thumbprint).
	if err := simpleoidc.SameCnfThumbprint(origIdt, reIdt); err != nil {
		return fmt.Errorf("refreshed ID Token has different cnf claim (key binding) than original ID Token: %w", err)
	}

	reJwt, err := simpleoidc.NewJwt(reIdt)
	if err != nil {
		return fmt.Errorf("error parsing refreshed ID token: %w", err)
	}
	if typ := reJwt.GetSignature().GetProtectedClaims().Type; typ != KEYBOUND_TYP {
		return fmt.Errorf("expected key-bound refreshed ID Token (typ=%s) but got typ=%s", KEYBOUND_TYP, typ)
	}

	// Verify the OP's signature on the refreshed ID Token, mirroring the
	// StandardOp refresh verification (StandardOpRefreshable.VerifyRefreshedIDToken).
	options := []rp.Option{}
	if r.HttpClient != nil {
		options = append(options, rp.WithHTTPClient(r.HttpClient))
	}
	// The redirect URI is not used when verifying a refreshed token.
	redirectURI := ""
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, r.issuer, r.clientID,
		r.ClientSecret, redirectURI, r.Scopes, options...)
	if err != nil {
		return fmt.Errorf("failed to create RP to verify token: %w", err)
	}
	if _, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(reIdt), relyingParty.IDTokenVerifier()); err != nil {
		return err
	}
	return nil
}

var _ RefreshableOpenIdProvider = (*KeyBindingOpRefreshable)(nil)
