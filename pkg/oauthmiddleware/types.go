package oauthmiddleware

import (
	"context"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type OAuth2Connector interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource
}

type IDTokenVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type IDTokenValidator func(token *oidc.IDToken) bool

type Config struct {
	OAuth2Connector OAuth2Connector
	IDTokenVerifier IDTokenVerifier
	Validators      []IDTokenValidator

	BasePath   string
	BeginParam string
}
