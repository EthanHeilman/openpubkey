// Copyright 2024 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package verifier_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/mocks"
	"github.com/openpubkey/openpubkey/client/providers/discover"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/require"
)

func TestVerifier(t *testing.T) {
	clientID := "verifier"
	commitmentClaim := "nonce"
	provider, err := mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": clientID,
	})
	require.NoError(t, err)

	providerGQ, err := mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": clientID,
	}, mocks.UseGQSign(true))
	require.NoError(t, err)

	opkClient, err := client.New(provider)
	require.NoError(t, err)
	pkt, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	// The below vanilla check is redundant since there is a final verification step as part of the PK token issuance
	pktVerifier, err := verifier.New(provider.Verifier())
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// Check if it handles more than one verifier
	pktVerifierTwoProviders, err := verifier.New(provider.Verifier(), verifier.AddProviderVerifiers(providerGQ.Verifier()))
	require.NoError(t, err)

	opkClient, err = client.New(providerGQ)
	require.NoError(t, err)
	pktGQ, err := opkClient.Auth(context.Background())
	require.NoError(t, err)

	err = pktVerifierTwoProviders.VerifyPKToken(context.Background(), pktGQ)
	require.NoError(t, err)

	// Check if verification fails with incorrect issuer
	wrongIssuer := "https://evil.com/"
	providerVerifier := verifier.NewProviderVerifier(wrongIssuer, commitmentClaim, verifier.ProviderVerifierOpts{SkipClientIDCheck: true})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// Check if verification fails with incorrect commitment claim
	wrongCommitmentClaim := "evil"
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), wrongCommitmentClaim, verifier.ProviderVerifierOpts{SkipClientIDCheck: true})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// When "aud" claim is a single string, check that Client ID is verified when specified correctly
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// When "aud" claim is a single string, check that an incorrect Client ID when specified, fails
	wrongClientID := "super_evil"
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: wrongClientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// If audience is a list of strings, make sure verification holds
	provider, err = mocks.NewMockOpenIdProvider(t, map[string]any{
		"aud": []string{clientID},
	})
	require.NoError(t, err)

	opkClient, err = client.New(provider)
	require.NoError(t, err)
	pkt, err = opkClient.Auth(context.Background())
	require.NoError(t, err)

	// When "aud" claim is a list of strings, check that Client ID is verified when specified correctly
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.NoError(t, err)

	// When "aud" claim is a list of strings, check that an incorrect Client ID when specified, fails
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: wrongClientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// Specify a custom public key discoverer that returns the incorrect key and check that verification fails
	alg := jwa.RS256
	signer, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwksFunc, err := discover.MockGetJwksByIssuerOneKey(signer.Public(), pkt.Op.ProtectedHeaders().KeyID(), string(alg))
	require.NoError(t, err)

	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{
		ClientID: clientID,
		DiscoverPublicKey: &discover.PublicKeyFinder{
			JwksFunc: jwksFunc,
		},
	})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt)
	require.Error(t, err)

	// When the PK token does not have a GQ signature but only GQ signatures are allowed, check that verification fails
	providerVerifier = verifier.NewProviderVerifier(provider.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	require.Error(t, err)

	// When the PK token has a GQ signature and only GQ signatures are allowed, check that verification succeeds
	opkClient, err = client.New(providerGQ)
	require.NoError(t, err)
	pkt, err = opkClient.Auth(context.Background())
	require.NoError(t, err)

	providerVerifier = verifier.NewProviderVerifier(providerGQ.Verifier().Issuer(), commitmentClaim, verifier.ProviderVerifierOpts{ClientID: clientID})
	pktVerifier, err = verifier.New(providerVerifier)
	require.NoError(t, err)
	err = pktVerifier.VerifyPKToken(context.Background(), pkt, verifier.GQOnly())
	require.NoError(t, err)
}

func TestGQCommitment(t *testing.T) {

	gqBindingAud := verifier.AudPrefixForGQCommitment + "1234"

	testCases := []struct {
		name         string
		aud          string
		expError     string
		gqSign       bool
		gqCommitment bool
		gqOnly       bool
	}{
		{name: "happy case", aud: gqBindingAud, expError: "",
			gqSign: true, gqCommitment: true, gqOnly: true},
		{name: "wrong aud prefix", aud: "bad value", expError: "error verifying PK Token: audience claim in PK Token's GQCommitment must be prefixed by",
			gqSign: true, gqCommitment: true, gqOnly: true},
		{name: "gqSign is false", aud: verifier.AudPrefixForGQCommitment, expError: "error requesting ID Token: if GQCommitment is true then GQSign must also be true",
			gqSign: false, gqCommitment: true, gqOnly: true},
		{name: "gqCommitment is false", aud: verifier.AudPrefixForGQCommitment, expError: "",
			gqSign: true, gqCommitment: false, gqOnly: true},
		{name: "gqOnly is false", aud: verifier.AudPrefixForGQCommitment, expError: "error verifying PK Token: GQCommitment requires that GQOnly is true, but GQOnly is (false)",
			gqSign: true, gqCommitment: true, gqOnly: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			provider, err := mocks.NewMockOpenIdProvider(t, map[string]any{
				"aud": tc.aud,
			}, mocks.UseGQSign(tc.gqSign), mocks.UseGQCommitment(tc.gqCommitment), mocks.UseGQOnly(tc.gqOnly))

			require.NoError(t, err)

			opkClient, err := client.New(provider)
			require.NoError(t, err)
			pkt, err := opkClient.Auth(context.Background())

			if tc.expError != "" {
				require.ErrorContains(t, err, tc.expError)
			} else {
				cicHash, ok := pkt.Op.ProtectedHeaders().Get("cic")
				if tc.gqCommitment == false {
					require.False(t, ok)
					require.Nil(t, cicHash)
				} else {
					require.True(t, ok)
					require.NotNil(t, cicHash)

					cic, err := pkt.GetCicValues()
					require.NoError(t, err)
					require.NotNil(t, cic)
					cicHashFromCIC, err := cic.Hash()
					require.NoError(t, err)
					require.Equal(t, string(cicHashFromCIC), cicHash, "CIC does not match cicHash in GQ commitment")
				}

				require.NoError(t, err)
				pktVerifier, err := verifier.New(provider.Verifier())
				require.NoError(t, err)
				err = pktVerifier.VerifyPKToken(context.Background(), pkt)
				require.NoError(t, err)
			}
		})
	}
}
