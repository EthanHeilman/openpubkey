// This code was originally generated by mockery v2.32.0 and modified

package mocks

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"time"

	"github.com/awnumar/memguard"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/verifier"
	"github.com/stretchr/testify/mock"
)

// OpenIdProvider is an autogenerated mock type for the OpenIdProvider type
type OpenIdProvider struct {
	mock.Mock
}

// Verifier provides a mock function with given fields:
func (_m *OpenIdProvider) Verifier() verifier.ProviderVerifier {
	ret := _m.Called()

	var r0 verifier.ProviderVerifier
	if rf, ok := ret.Get(0).(func() verifier.ProviderVerifier); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(verifier.ProviderVerifier)
		}
	}

	return r0
}

// PublicKey provides a mock function with given fields: ctx, headers

func (_m *OpenIdProvider) PublicKey(ctx context.Context, headers jws.Headers) (crypto.PublicKey, error) {
	ret := _m.Called(ctx, headers)
	var r0 crypto.PublicKey
	var r1 error

	if rf, ok := ret.Get(0).(func(context.Context, jws.Headers) (crypto.PublicKey, error)); ok {
		return rf(ctx, headers)
	}

	if rf, ok := ret.Get(0).(func(context.Context, jws.Headers) crypto.PublicKey); ok {
		r0 = rf(ctx, headers)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(crypto.PublicKey)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, jws.Headers) error); ok {
		r1 = rf(ctx, headers)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1

}

// RequestTokens provides a mock function with given fields: ctx, cicHash
func (_m *OpenIdProvider) RequestTokens(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
	ret := _m.Called(ctx, cicHash)

	var r0 *memguard.LockedBuffer
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*memguard.LockedBuffer, error)); ok {
		return rf(ctx, cicHash)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *memguard.LockedBuffer); ok {
		r0 = rf(ctx, cicHash)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*memguard.LockedBuffer)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, cicHash)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewOpenIdProvider creates a new instance of OpenIdProvider. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewOpenIdProvider(t interface {
	mock.TestingT
	Cleanup(func())
}) *OpenIdProvider {
	mock := &OpenIdProvider{}
	mock.Mock.Test(t)

	return mock
}

// This function creates a new, correctly functioning Provider that can be used for test purposes, for finer grain control
// or error testing, please use the function above.
//
// extraClaims: Allows for optional id token payload values to be supplied, these values will overwrite existing ones of the same name.
func NewMockOpenIdProvider(
	t interface {
		mock.TestingT
		Cleanup(func())
	},
	extraClaims map[string]any,
) (*OpenIdProvider, error) {
	alg := jwa.RS256
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	oidpServer, err := NewOIDPServer(signingKey, alg)
	if err != nil {
		return nil, err
	}
	if err := oidpServer.Serve(); err != nil {
		return nil, err
	}
	t.Cleanup(func() { oidpServer.Shutdown() })

	// Use our OIDP server uri as the mock issuer
	issuer := oidpServer.URI()

	provider := NewOpenIdProvider(t)
	provider.On("Verifier").Return(verifier.NewProviderVerifier(issuer, "nonce", verifier.ProviderVerifierOpts{SkipClientIDCheck: true}))
	provider.On("PublicKey", mock.Anything, mock.Anything).Return(signingKey.Public(), nil)
	provider.On("RequestTokens", mock.Anything, mock.Anything).Return(func(ctx context.Context, cicHash string) (*memguard.LockedBuffer, error) {
		headers := jws.NewHeaders()
		headers.Set(jws.AlgorithmKey, alg)
		headers.Set(jws.KeyIDKey, oidpServer.KID())
		headers.Set(jws.TypeKey, "JWT")

		// Default, minimum viable claims for functional id token payload
		payload := map[string]any{
			"sub":   "me",
			"aud":   "also me",
			"iss":   issuer,
			"iat":   time.Now().Unix(),
			"nonce": cicHash,
		}
		// Add/replace values in payload map with those provided
		for k, v := range extraClaims {
			payload[k] = v
		}

		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}

		token, err := jws.Sign(
			payloadBytes,
			jws.WithKey(
				alg,
				signingKey,
				jws.WithProtectedHeaders(headers),
			),
		)

		return memguard.NewBufferFromBytes(token), err
	})

	return provider, nil
}