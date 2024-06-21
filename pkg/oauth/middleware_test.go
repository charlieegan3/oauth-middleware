package middlewares

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Mock implementations and test setup

type mockOAuth2Connector struct {
	tokenSource oauth2.TokenSource
}

func (*mockOAuth2Connector) Exchange(_ context.Context, _ string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}

func (*mockOAuth2Connector) AuthCodeURL(_ string) string {
	return "http://example.com/auth"
}

func (c *mockOAuth2Connector) TokenSource(_ context.Context, _ *oauth2.Token) oauth2.TokenSource {
	return c.tokenSource
}

type mockTokenSource struct {
	returnError string
}

func (ts *mockTokenSource) Token() (*oauth2.Token, error) {
	if ts.returnError != "" {
		return nil, fmt.Errorf("mock token source failed with preset error: %s", ts.returnError)
	}

	return &oauth2.Token{
		AccessToken: "foobar",
	}, nil
}

type matchingTokenVerifier struct {
	match string
}

func (v *matchingTokenVerifier) Verify(_ *http.Request, token string) (*oidc.IDToken, error) {
	if token != v.match {
		return nil, errors.New("invalid token")
	}

	return &oidc.IDToken{}, nil
}

func allowAllTokenValidator(_ *oidc.IDToken) bool {
	return true
}

func TestBeginParam(t *testing.T) {
	t.Parallel()

	handler := InitMiddlewareAuth(
		&mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		&matchingTokenVerifier{},
		"/base",
		"secret",
		[]IDTokenValidator{allowAllTokenValidator},
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/base", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNotFound {
		t.Fatalf("Expected status code %d, got %d", http.StatusNotFound, resp.Code)
	}

	// make the request with the beginParam set to secret
	req = httptest.NewRequest(http.MethodGet, "/base?secret=1", nil)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusFound {
		t.Fatalf("Expected status code %d, got %d", http.StatusSeeOther, resp.Code)
	}

	if got, exp := resp.Header().Get("Location"), "http://example.com/auth"; !strings.HasPrefix(got, exp) {
		t.Fatalf("Expected redirect location %s, got %s", exp, got)
	}
}

func TestValidToken(t *testing.T) {
	t.Parallel()

	handler := InitMiddlewareAuth(
		&mockOAuth2Connector{
			&mockTokenSource{},
		},
		&matchingTokenVerifier{"valid-token"},
		"/",
		"secret",
		[]IDTokenValidator{allowAllTokenValidator},
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/foobar", nil)

	req.Header.Set("Cookie", "token=valid-token")

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, resp.Code)
	}
}

func TestInvalidToken(t *testing.T) {
	t.Parallel()

	handler := InitMiddlewareAuth(
		&mockOAuth2Connector{
			&mockTokenSource{},
		},
		&matchingTokenVerifier{"valid-token"},
		"/",
		"secret",
		[]IDTokenValidator{allowAllTokenValidator},
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/foobar", nil)

	req.Header.Set("Cookie", "token=not-valid-token")

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if exp, got := http.StatusUnauthorized, resp.Code; exp != got {
		t.Fatalf("Expected status code %d, got %d", exp, got)
	}
}

func TestRefreshToken(t *testing.T) {
	t.Parallel()

	handler := InitMiddlewareAuth(
		&mockOAuth2Connector{
			&mockTokenSource{},
		},
		&matchingTokenVerifier{"valid-token"},
		"/",
		"secret",
		[]IDTokenValidator{allowAllTokenValidator},
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/foobar", nil)

	req.Header.Set("Cookie", "token=not-valid-token")
	req.Header.Set("Cookie", "refresh_token=valid-token")

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if exp, got := http.StatusOK, resp.Code; exp != got {
		t.Fatalf("Expected status code %d, got %d", exp, got)
	}

	if exp, got := "foobar", resp.Header().Get("Set-Cookie"); !strings.Contains(got, exp) {
		t.Fatalf("Expected response to contain %s, got %s", exp, got)
	}
}

func TestExpiredTokenAndRefresh(t *testing.T) {
	t.Parallel()

	handler := InitMiddlewareAuth(
		&mockOAuth2Connector{
			&mockTokenSource{
				returnError: "refresh expired",
			},
		},
		&matchingTokenVerifier{},
		"/base",
		"secret",
		[]IDTokenValidator{allowAllTokenValidator},
	)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/base", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusNotFound {
		t.Fatalf("Expected status code %d, got %d", http.StatusNotFound, resp.Code)
	}

	// make the request with the beginParam set to secret
	req = httptest.NewRequest(http.MethodGet, "/base?secret=1", nil)
	req.Header.Set("Cookie", "refresh_token=invalid-token")

	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if exp, got := http.StatusFound, resp.Code; exp != got {
		t.Fatalf("Expected status code %d, got %d", exp, got)
	}

	if got, exp := resp.Header().Get("Location"), "http://example.com/auth"; !strings.HasPrefix(got, exp) {
		t.Fatalf("Expected redirect location %s, got %s", exp, got)
	}
}
