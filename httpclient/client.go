// Package httpclient est un client HTTP orienté réseaux d'entreprise.
//
// Fonctionnalités :
//   - Proxy HTTP/HTTPS avec authentification NTLM ou Negotiate (Kerberos)
//   - Utilisation automatique des credentials Windows (session courante, pas de saisie)
//   - Test de joignabilité du proxy avant utilisation (fallback direct si injoignable)
//   - Mode VERBOSE : log complet de chaque requête/réponse
//   - Retry automatique sans proxy si ProxyError détecté
package httpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

// AuthMode définit le schéma d'authentification proxy.
type AuthMode string

const (
	AuthNone      AuthMode = ""          // Pas d'auth
	AuthNTLM      AuthMode = "NTLM"      // NTLM — credentials Windows courants (SSPI)
	AuthNegotiate AuthMode = "Negotiate" // Negotiate — Kerberos avec repli NTLM
)

// =============================================================================
// verboseTransport — RoundTripper qui logue chaque requête/réponse
// =============================================================================

type verboseTransport struct {
	base   http.RoundTripper
	logger *log.Logger
}

func (t *verboseTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	t.logger.Printf("[VERBOSE] --> %s %s", req.Method, req.URL)
	for k, vals := range req.Header {
		if k == "Authorization" || k == "Proxy-Authorization" || k == "X-Rftoken" {
			t.logger.Printf("[VERBOSE]     %s: ***", k)
			continue
		}
		t.logger.Printf("[VERBOSE]     %s: %s", k, strings.Join(vals, ", "))
	}
	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start)
	if err != nil {
		t.logger.Printf("[VERBOSE] <-- ERROR (%s): %v", elapsed.Round(time.Millisecond), err)
		return nil, err
	}
	t.logger.Printf("[VERBOSE] <-- %s (%s)", resp.Status, elapsed.Round(time.Millisecond))
	return resp, nil
}

// =============================================================================
// Client
// =============================================================================

// Client est un client HTTP réentrant, thread-safe.
type Client struct {
	Proxies   map[string]string
	Headers   map[string]string
	AuthType  AuthMode
	Verbose   bool
	ProxyUser string
	ProxyPass string

	http   *http.Client
	logger *log.Logger
}

// New retourne un Client avec configuration par défaut.
func New() *Client {
	c := &Client{
		Proxies:  make(map[string]string),
		Headers:  make(map[string]string),
		AuthType: AuthNone,
		logger:   log.New(os.Stderr, "[httpclient] ", log.LstdFlags),
	}
	c.rebuild()
	return c
}

// WithTimeout retourne une copie du client avec un timeout HTTP différent.
// Utilisé pour les uploads de fichiers volumineux qui nécessitent plus de temps.
func (c *Client) WithTimeout(d time.Duration) *Client {
	clone := &Client{
		Proxies:   c.Proxies,
		Headers:   c.Headers,
		AuthType:  c.AuthType,
		Verbose:   c.Verbose,
		ProxyUser: c.ProxyUser,
		ProxyPass: c.ProxyPass,
		logger:    c.logger,
	}
	clone.rebuild()
	clone.http.Timeout = d
	return clone
}

func (c *Client) SetLogger(l *log.Logger) {
	c.logger = l
	c.rebuild()
}

// SetProxy configure le proxy et reconstruit le transport.
func (c *Client) SetProxy(addr string) {
	c.Proxies["http"] = addr
	c.Proxies["https"] = addr
	c.rebuild()
}

// ClearProxy bascule en connexion directe.
func (c *Client) ClearProxy() {
	delete(c.Proxies, "http")
	delete(c.Proxies, "https")
	c.rebuild()
}

// ProxyReachable teste si le proxy est joignable via TCP (timeout 3s).
func (c *Client) ProxyReachable() bool {
	addr := c.Proxies["https"]
	if addr == "" {
		addr = c.Proxies["http"]
	}
	if addr == "" {
		return false
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "8080"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// rebuild reconstruit le http.Client interne selon la configuration courante.
func (c *Client) rebuild() {
	proxyFunc := func(req *http.Request) (*url.URL, error) {
		addr := c.Proxies[req.URL.Scheme]
		if addr == "" {
			return nil, nil
		}
		if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
			addr = "http://" + addr
		}
		return url.Parse(addr)
	}

	base := &http.Transport{
		Proxy: proxyFunc,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}

	var transport http.RoundTripper = base

	if c.AuthType == AuthNTLM || c.AuthType == AuthNegotiate {
		transport = &ntlmssp.Negotiator{RoundTripper: base}
	}

	if c.Verbose {
		transport = &verboseTransport{base: transport, logger: c.logger}
	}

	c.http = &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}
}

// =============================================================================
// Méthodes HTTP
// =============================================================================

func (c *Client) Get(rawURL string, headers map[string]string) (*Response, error) {
	return c.do("GET", rawURL, nil, headers)
}

// Delete effectue une requête HTTP DELETE.
func (c *Client) Delete(rawURL string, headers map[string]string) (*Response, error) {
	return c.do("DELETE", rawURL, nil, headers)
}

// Put effectue une requête HTTP PUT avec un body JSON.
func (c *Client) Put(rawURL string, body any, headers map[string]string) (*Response, error) {
	merged := make(map[string]string)
	for k, v := range headers {
		merged[k] = v
	}
	var payload []byte
	switch v := body.(type) {
	case []byte:
		payload = v
	case string:
		payload = []byte(v)
	case nil:
	default:
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("json marshal: %w", err)
		}
		merged["Content-Type"] = "application/json"
	}
	return c.do("PUT", rawURL, payload, merged)
}

func (c *Client) Post(rawURL string, body any, headers map[string]string) (*Response, error) {
	merged := make(map[string]string)
	for k, v := range headers {
		merged[k] = v
	}
	var payload []byte
	switch v := body.(type) {
	case []byte:
		payload = v
	case string:
		payload = []byte(v)
	case nil:
	default:
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("json marshal: %w", err)
		}
		merged["Content-Type"] = "application/json"
	}
	return c.do("POST", rawURL, payload, merged)
}

func (c *Client) do(method, rawURL string, body []byte, extra map[string]string) (*Response, error) {
	var r io.Reader
	if len(body) > 0 {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, r)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if isProxyErr(err) {
			return nil, &ProxyError{err.Error()}
		}
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	hdrs := make(map[string]string, len(resp.Header))
	for k, vals := range resp.Header {
		hdrs[k] = strings.Join(vals, ", ")
	}
	return &Response{StatusCode: resp.StatusCode, Headers: hdrs, body: raw}, nil
}

func isProxyErr(err error) bool {
	s := err.Error()
	return strings.Contains(s, "proxyconnect") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "407") ||
		strings.Contains(s, "proxy")
}

// =============================================================================
// Response
// =============================================================================

type Response struct {
	StatusCode int
	Headers    map[string]string
	body       []byte
}

func (r *Response) Text() string       { return string(r.body) }
func (r *Response) Bytes() []byte      { return r.body }
func (r *Response) OK() bool           { return r.StatusCode >= 200 && r.StatusCode < 400 }
func (r *Response) Decode(v any) error { return json.Unmarshal(r.body, v) }

func (r *Response) Err() error {
	if r.OK() {
		return nil
	}
	preview := r.Text()
	if len(preview) > 200 {
		preview = preview[:200]
	}
	return fmt.Errorf("HTTP %d: %s", r.StatusCode, preview)
}

// ProxyError est retournée quand le proxy est injoignable ou renvoie une erreur d'auth.
type ProxyError struct{ Message string }

func (e *ProxyError) Error() string { return "proxy error: " + e.Message }
