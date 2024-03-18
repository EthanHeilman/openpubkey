package providers

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"
)

func CreateGQToken(ctx context.Context, idToken []byte, op OpenIdProvider) ([]byte, error) {
	headersB64, _, _, err := jws.SplitCompact(idToken)
	if err != nil {
		return nil, fmt.Errorf("error getting original headers: %w", err)
	}

	// TODO: We should create a util function for extracting headers from tokens
	headersJson, err := util.Base64DecodeForJWT(headersB64)
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding GQ kid: %w", err)
	}
	headers := jws.NewHeaders()
	err = json.Unmarshal(headersJson, &headers)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling GQ kid to original headers: %w", err)
	}

	opKey, err := op.PublicKeyByToken(ctx, idToken)
	if err != nil {
		return nil, err
	}

	if opKey.Alg != "RS256" {
		return nil, fmt.Errorf("gq signatures require original provider to have signed with an RSA key, jWK.alg was (%s)", opKey.Alg)
	}

	rsaKey, ok := opKey.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("gq signatures require original provider to have signed with an RSA key")
	}
	return gq.GQ256SignJWT(rsaKey, idToken)
}
