package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"

	"github.com/charlieegan3/oauth-middleware/pkg/oauthmiddleware"
)

type Config struct {
	ProviderURL string `yaml:"provider_url"`

	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`

	BasePath   string `yaml:"base_path"`
	BeginParam string `yaml:"begin_param"`
}

func main() {
	bs, err := os.ReadFile("config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read config file: %v\n", err)

		return
	}

	var c Config
	if err := yaml.Unmarshal(bs, &c); err != nil {
		fmt.Fprintf(os.Stderr, "failed to unmarshal config file: %v\n", err)

		return
	}

	oidcProvider, err := oidc.NewProvider(context.TODO(), c.ProviderURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create oidc provider: %v\n", err)

		return
	}

	oauth2Config := &oauth2.Config{
		Endpoint:     oidcProvider.Endpoint(),
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
	}

	serverHost := "localhost:3000"

	oauth2Config.RedirectURL = fmt.Sprintf(
		"http://%s/%s/auth/callback",
		serverHost,
		strings.TrimPrefix(c.BasePath, "/"),
	)
	oauth2Config.Scopes = c.Scopes

	tokenVerifier := oidcProvider.Verifier(&oidc.Config{ClientID: oauth2Config.ClientID})

	mwCfg := &oauthmiddleware.Config{
		OAuth2Connector: oauth2Config,
		IDTokenVerifier: tokenVerifier,
		Validators:      []oauthmiddleware.IDTokenValidator{},
		AuthBasePath:    c.BasePath,
		BeginParam:      c.BeginParam,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", echo)

	mw, err := oauthmiddleware.Init(mwCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create oauth middleware: %v\n", err)

		return
	}

	srv := &http.Server{
		Addr:              serverHost,
		Handler:           mw(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
	}
}

func echo(w http.ResponseWriter, r *http.Request) {
	jsonHeaders := make(map[string][]string)
	for k, v := range r.Header {
		jsonHeaders[k] = v
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	err := enc.Encode(struct {
		Method           string               `json:"method"`
		Host             string               `json:"host"`
		Proto            string               `json:"proto"`
		URL              string               `json:"url"`
		RequestURI       string               `json:"request_uri"`
		RemoteAddr       string               `json:"remote_addr"`
		ContentLength    int64                `json:"content_length"`
		TransferEncoding []string             `json:"transfer_encoding"`
		TLS              *tls.ConnectionState `json:"tls"`
		Headers          map[string][]string  `json:"headers"`
	}{
		Method:        r.Method,
		Host:          r.Host,
		Proto:         r.Proto,
		URL:           r.URL.String(),
		ContentLength: r.ContentLength,
		RemoteAddr:    r.RemoteAddr,
		RequestURI:    r.RequestURI,
		TLS:           r.TLS,
		Headers:       jsonHeaders,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}
}
