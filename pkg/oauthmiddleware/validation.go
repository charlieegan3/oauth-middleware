package oauthmiddleware

import (
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc"
)

func checkToken(
	r *http.Request,
	idTokenVerifier IDTokenVerifier,
	tokenValue string,
	validators []IDTokenValidator,
) (bool, error) {
	idToken, err := idTokenVerifier.Verify(r.Context(), tokenValue)
	if err != nil {
		return false, fmt.Errorf("failed to verify id token: %w", err)
	}

	if !validateIDToken(idToken, validators...) {
		return false, nil
	}

	return true, nil
}

func validateIDToken(token *oidc.IDToken, validators ...IDTokenValidator) bool {
	for _, validator := range validators {
		if !validator(token) {
			return false
		}
	}

	return true
}
