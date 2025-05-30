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

package providers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

const userInfoResponse = `{
	"sub": "me",
	"email": "alice@example.com",
	"name": "Alice Example"
}`

func TestGoogleSimpleRequest(t *testing.T) {
	gqSign := false

	issuer := googleIssuer
	providerOverride, err := mocks.NewMockProviderBackend(issuer, "RS256", 2)
	require.NoError(t, err)

	httpClient := mocks.NewMockGoogleUserInfoHTTPClient(userInfoResponse)

	op := &GoogleOp{
		StandardOp{
			issuer:                    googleIssuer,
			publicKeyFinder:           providerOverride.PublicKeyFinder,
			requestTokensOverrideFunc: providerOverride.RequestTokensOverrideFunc,
			HttpClient:                httpClient,
		},
	}

	cic := GenCIC(t)
	expSigningKey, expKeyID, expRecord := providerOverride.RandomSigningKey()

	idTokenTemplate := mocks.IDTokenTemplate{
		CommitFunc:           mocks.AddNonceCommit,
		Issuer:               issuer,
		Nonce:                "empty",
		NoNonce:              false,
		Aud:                  "also me",
		KeyID:                expKeyID,
		NoKeyID:              false,
		Alg:                  expRecord.Alg,
		NoAlg:                false,
		ExtraClaims:          map[string]any{"extraClaim": "extraClaimValue"},
		ExtraProtectedClaims: map[string]any{"extraHeader": "extraheaderValue"},
		SigningKey:           expSigningKey,
	}
	providerOverride.SetIDTokenTemplate(&idTokenTemplate)

	tokens, err := op.RequestTokens(context.Background(), cic)
	require.NoError(t, err)
	idToken := tokens.IDToken

	cicHash, err := cic.Hash()
	require.NoError(t, err)
	require.NotNil(t, cicHash)

	headerB64, payloadB64, _, err := jws.SplitCompact(idToken)
	require.NoError(t, err)
	headerJson, err := util.Base64DecodeForJWT(headerB64)
	require.NoError(t, err)

	if gqSign {
		headers := jws.NewHeaders()
		err = json.Unmarshal(headerJson, &headers)
		require.NoError(t, err)
		cicHash2, ok := headers.Get("cic")
		require.True(t, ok, "cic not found in GQ ID Token")
		require.Equal(t, string(cicHash), cicHash2, "cic hash in jwt header should match cic supplied")
	} else {
		payload, err := util.Base64DecodeForJWT(payloadB64)
		require.NoError(t, err)
		require.Contains(t, string(payload), string(cicHash))
	}

	require.Equal(t, "mock-refresh-token", string(tokens.RefreshToken))
	require.Equal(t, "mock-access-token", string(tokens.AccessToken))

	userInfoJson, err := op.UserInfo(context.Background(), tokens.AccessToken, "me")
	require.NoError(t, err)

	require.Contains(t, userInfoJson, `"email":"alice@example.com"`)
	require.Contains(t, userInfoJson, `"sub":"me"`)
}
