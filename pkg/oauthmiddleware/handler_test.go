package oauthmiddleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type mockOAuth2Connector struct {
	tokenSource oauth2.TokenSource
}

func (*mockOAuth2Connector) Exchange(
	_ context.Context,
	_ string,
	_ ...oauth2.AuthCodeOption,
) (*oauth2.Token, error) {
	t := &oauth2.Token{}

	t = t.WithExtra(map[string]interface{}{
		"id_token": "valid-token",
	})

	return t, nil
}

func (*mockOAuth2Connector) AuthCodeURL(_ string, _ ...oauth2.AuthCodeOption) string {
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

func (v *matchingTokenVerifier) Verify(_ context.Context, token string) (*oidc.IDToken, error) {
	if token != v.match {
		return nil, errors.New("invalid token")
	}

	return &oidc.IDToken{}, nil
}

func allowAllTokenValidator(_ *oidc.IDToken) (map[any]any, bool) {
	return nil, true
}

func setFooTokenValidator(_ *oidc.IDToken) (map[any]any, bool) {
	return map[any]any{
		"foo": "bar",
	}, true
}

func TestBeginParam(t *testing.T) {
	t.Parallel()

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		IDTokenVerifier: &matchingTokenVerifier{},
		AuthBasePath:    "/base",
		BeginParam:      "secret",
		Validators:      []IDTokenValidator{allowAllTokenValidator},
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	req = httptest.NewRequest(http.MethodGet, "/base?secret=1", nil)
	resp = httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusFound {
		t.Fatalf("Expected status code %d, got %d", http.StatusFound, resp.Code)
	}

	if got, exp := resp.Header().Get("Location"), "http://example.com/auth"; !strings.HasPrefix(got, exp) {
		t.Fatalf("Expected redirect location %s, got %s", exp, got)
	}
}

func TestUnsetBeginParam(t *testing.T) {
	t.Parallel()

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		IDTokenVerifier: &matchingTokenVerifier{},
		AuthBasePath:    "/base",
		BeginParam:      "",
		Validators:      []IDTokenValidator{allowAllTokenValidator},
		Debug:           true,
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/base", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if exp, got := http.StatusFound, resp.Code; exp != got {
		t.Fatalf("Expected status code %d, got %d", exp, got)
	}
}

func TestValidToken(t *testing.T) {
	t.Parallel()

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		IDTokenVerifier: &matchingTokenVerifier{"valid-token"},
		AuthBasePath:    "/",
		BeginParam:      "secret",
		Validators:      []IDTokenValidator{setFooTokenValidator},
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctxVal := r.Context().Value("foo")

		if ctxVal == nil {
			t.Fatal("Expected context value to be not nil, got nil")
		}

		val, ok := ctxVal.(string)
		if !ok {
			t.Fatalf("Expected context value to be %s, got %s", "bar", ctxVal)
		}

		if exp, got := "bar", val; exp != got {
			t.Fatalf("Expected context value to be %s, got %s", exp, got)
		}

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

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		IDTokenVerifier: &matchingTokenVerifier{"valid-token"},
		AuthBasePath:    "/",
		BeginParam:      "secret",
		Validators:      []IDTokenValidator{allowAllTokenValidator},
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		IDTokenVerifier: &matchingTokenVerifier{"valid-token"},
		AuthBasePath:    "/",
		BeginParam:      "secret",
		Validators:      []IDTokenValidator{allowAllTokenValidator},
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{
				returnError: "refresh expired",
			},
		},
		IDTokenVerifier: &matchingTokenVerifier{},
		AuthBasePath:    "/base",
		BeginParam:      "secret",
		Validators:      []IDTokenValidator{allowAllTokenValidator},
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestCallback(t *testing.T) {
	t.Parallel()

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		IDTokenVerifier:  &matchingTokenVerifier{"valid-token"},
		AuthBasePath:     "/",
		CallbackBasePath: "/",
		BeginParam:       "secret",
		Validators:       []IDTokenValidator{allowAllTokenValidator},
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	stateBs, err := json.Marshal(state{
		Destination: "https://example.com/",
		Token:       "foo",
	})
	if err != nil {
		t.Fatalf("Failed to marshal state: %v", err)
	}

	stateParam := base64.RawURLEncoding.EncodeToString(stateBs)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/callback?state=%s&code=1234", stateParam), nil)
	req.Header.Set("Cookie", "state_token="+base64.RawURLEncoding.EncodeToString([]byte("foo")))

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if exp, got := 302, resp.Code; exp != got {
		t.Fatalf("Expected status code %d, got %d", exp, got)
	}

	if exp, got := "https://example.com/", resp.Header().Get("Location"); exp != got {
		t.Fatalf("Expected redirect location %s, got %s", exp, got)
	}

	if resp.Header().Get("Set-Cookie") == "" {
		t.Fatalf("Expected a cookie to be set, got none")
	}
}

func TestUnrelatedPath(t *testing.T) {
	t.Parallel()

	mw, err := Init(&Config{
		OAuth2Connector: &mockOAuth2Connector{
			tokenSource: &mockTokenSource{},
		},
		IDTokenVerifier: &matchingTokenVerifier{},
		AuthBasePath:    "/admin",
		BeginParam:      "notused",
		Validators:      []IDTokenValidator{},
	})
	if err != nil {
		t.Fatalf("Failed to initialize handler: %v", err)
	}

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	server := httptest.NewServer(handler)
	defer server.Close()

	req := httptest.NewRequest(http.MethodGet, "/foo", nil)

	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Fatalf("Expected status code %d, got %d", http.StatusOK, resp.Code)
	}
}
