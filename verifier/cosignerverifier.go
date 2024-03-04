package verifier

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken"
	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

type JSONWebKey = jwk.Key

type DefaultCosignerVerifier struct {
	issuer  string
	options CosignerVerifierOpts
}

type CosignerVerifierOpts struct {
	// Strict specifies whether or not a pk token MUST contain a signature by this cosigner.
	// Defaults to true.
	Strict *bool
	// Allows users to set custom function for discovering public key of Cosigner
	DiscoverPublicKey func(ctx context.Context, kid string, issuer string) (JSONWebKey, error)
}

func NewCosignerVerifier(issuer string, options CosignerVerifierOpts) *DefaultCosignerVerifier {
	v := &DefaultCosignerVerifier{
		issuer:  issuer,
		options: options,
	}

	// If no custom DiscoverPublicKey function is set, set default
	if v.options.DiscoverPublicKey == nil {
		v.options.DiscoverPublicKey = discoverCosignerPublicKey
	}

	if v.options.Strict == nil {
		*v.options.Strict = true
	}

	return v
}

func (v *DefaultCosignerVerifier) Issuer() string {
	return v.issuer
}

func (v *DefaultCosignerVerifier) Strict() bool {
	return *v.options.Strict
}

func (v *DefaultCosignerVerifier) VerifyCosigner(ctx context.Context, pkt *pktoken.PKToken) error {
	if pkt.Cos == nil {
		return fmt.Errorf("no cosigner signature")
	}

	cosToken, err := pkt.Compact(pkt.Cos)
	if err != nil {
		return err
	}

	// Parse our header
	header, err := pkt.ParseCosignerClaims()
	if err != nil {
		return err
	}

	key, err := v.options.DiscoverPublicKey(ctx, header.KeyID, header.Issuer)
	if err != nil {
		return err
	}

	// Check if it's expired
	if time.Now().After(time.Unix(header.Expiration, 0)) {
		return fmt.Errorf("cosigner signature expired")
	}

	if header.Algorithm != key.Algorithm().String() {
		return fmt.Errorf("key (kid=%s) has alg (%s) which doesn't match alg (%s) in protected", key.KeyID(), key.Algorithm(), header.Algorithm)
	}

	_, err = jws.Verify(cosToken, jws.WithKey(jwa.KeyAlgorithmFrom(key.Algorithm()), key))

	return err
}

func discoverCosignerPublicKey(ctx context.Context, kid string, issuer string) (JSONWebKey, error) {
	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}
	set, err := jwk.Fetch(context.Background(), discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public keys from Cosigner JWKS endpoint: %w", err)
	}

	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("missing key id (kid)")
	}

	return key, nil
}
