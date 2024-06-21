package oauthmiddleware

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

type state struct {
	Destination string `json:"destination"`
	Token       string `json:"token"`
}

func generateStateToken() (string, error) {
	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to generate state token: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
