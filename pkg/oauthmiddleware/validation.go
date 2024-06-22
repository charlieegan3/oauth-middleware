package oauthmiddleware

import (
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
)

func checkToken(
	r *http.Request,
	idTokenVerifier IDTokenVerifier,
	tokenValue string,
	validators []IDTokenValidator,
	debug bool,
) (bool, error) {
	idToken, err := idTokenVerifier.Verify(r.Context(), tokenValue)
	if err != nil {
		if debug {
			log.Printf("failed to verify id token: %v\n", err)
		}

		return false, fmt.Errorf("failed to verify id token: %w", err)
	}

	if !validateIDToken(debug, idToken, validators...) {
		if debug {
			log.Println("id token validation failed")
		}

		return false, nil
	}

	return true, nil
}

func validateIDToken(debug bool, token *oidc.IDToken, validators ...IDTokenValidator) bool {
	for i, validator := range validators {
		if debug {
			log.Println("running validator", i)
		}

		if !validator(token) {
			return false
		}
	}

	return true
}
