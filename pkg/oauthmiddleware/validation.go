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
) (map[any]any, bool, error) {
	idToken, err := idTokenVerifier.Verify(r.Context(), tokenValue)
	if err != nil {
		if debug {
			log.Printf("failed to verify id token: %v\n", err)
		}

		return nil, false, fmt.Errorf("failed to verify id token: %w", err)
	}

	ctxValues, validated := validateIDToken(debug, idToken, validators...)
	if !validated {
		if debug {
			log.Println("id token validation failed")
		}

		return nil, false, nil
	}

	return ctxValues, true, nil
}

func validateIDToken(debug bool, token *oidc.IDToken, validators ...IDTokenValidator) (map[any]any, bool) {
	ctxValues := make(map[any]any)

	for i, validator := range validators {
		if debug {
			log.Println("running validator", i)
		}

		values, validated := validator(token)
		if !validated {
			if debug {
				log.Println("validator failed")
			}

			return ctxValues, false
		}

		for k, v := range values {
			if debug {
				log.Printf("setting context value %s to %v\n", k, v)
			}

			ctxValues[k] = v
		}
	}

	return ctxValues, true
}
