// Package fortigate is a client for the FortiOS REST API (cmdb/system/dns-database).
package fortigate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Entry is one row of the dns-entry table of a dns-database zone.
// Field names follow the CLI "set" names of FortiOS 6.2 and later.
type Entry struct {
	ID            int    `json:"id"`
	Status        string `json:"status,omitempty"`
	Type          string `json:"type"`
	TTL           int64  `json:"ttl"`
	Preference    int    `json:"preference,omitempty"`
	IP            string `json:"ip,omitempty"`
	IPv6          string `json:"ipv6,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	CanonicalName string `json:"canonical-name,omitempty"`
}

// Zone is a dns-database zone. Only the fields used here are kept.
type Zone struct {
	Name    string  `json:"name"`
	Domain  string  `json:"domain"`
	Entries []Entry `json:"dns-entry"`
}

// Config configures a Client.
type Config struct {
	BaseURL            string // for example https://192.168.99.129
	Token              string // API key of the REST API administrator (config system api-user)
	VDOM               string // omitted from requests when empty
	TokenInQuery       bool   // send the key as the access_token query parameter (for versions that reject the Authorization header)
	CAFile             string // CA bundle (PEM) used to verify the FortiGate certificate
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// Client is a FortiOS REST API client.
type Client struct {
	cfg  Config
	base *url.URL
	http *http.Client
}

// New creates a Client.
func New(cfg Config) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("invalid FortiGate URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid FortiGate URL: %q", cfg.BaseURL)
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("FortiGate API key is not set")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // only when explicitly requested
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("cannot read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in CA file: %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	return &Client{cfg: cfg, base: base, http: &http.Client{Transport: tr, Timeout: timeout}}, nil
}

type response struct {
	Status     string          `json:"status"`
	HTTPStatus int             `json:"http_status"`
	Results    json.RawMessage `json:"results"`
	Error      int             `json:"error"`
	CLIError   string          `json:"cli_error"`
}

func (c *Client) zoneURL(name string) string {
	u := *c.base
	u.Path = c.base.Path + "/api/v2/cmdb/system/dns-database/" + url.PathEscape(name)
	u.RawPath = c.base.Path + "/api/v2/cmdb/system/dns-database/" + url.PathEscape(name)
	q := url.Values{}
	if c.cfg.VDOM != "" {
		q.Set("vdom", c.cfg.VDOM)
	}
	if c.cfg.TokenInQuery {
		q.Set("access_token", c.cfg.Token)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) do(ctx context.Context, method, name string, body any) (*response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.zoneURL(name), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !c.cfg.TokenInQuery {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		// The URL may contain access_token, so do not include the url.Error URL.
		if ue, ok := err.(*url.Error); ok {
			return nil, fmt.Errorf("%s dns-database/%s: %w", method, name, ue.Err)
		}
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var r response
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &r); err != nil && res.StatusCode < 300 {
			return nil, fmt.Errorf("%s dns-database/%s: cannot parse response: %w", method, name, err)
		}
	}
	if res.StatusCode >= 300 || (r.Status != "" && r.Status != "success") {
		msg := r.CLIError
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
			if len(msg) > 200 {
				msg = msg[:200]
			}
		}
		return nil, &APIError{Method: method, Zone: name, StatusCode: res.StatusCode, Code: r.Error, Message: msg}
	}
	return &r, nil
}

// APIError is returned when the FortiGate reports a failure.
type APIError struct {
	Method     string
	Zone       string
	StatusCode int
	Code       int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s dns-database/%s: HTTP %d (error %d): %s", e.Method, e.Zone, e.StatusCode, e.Code, e.Message)
}

// GetZone reads a zone.
func (c *Client) GetZone(ctx context.Context, name string) (*Zone, error) {
	r, err := c.do(ctx, http.MethodGet, name, nil)
	if err != nil {
		return nil, err
	}
	var zones []Zone
	if err := json.Unmarshal(r.Results, &zones); err != nil {
		// Some versions return an object instead of an array when a single mkey is requested.
		var z Zone
		if err2 := json.Unmarshal(r.Results, &z); err2 != nil {
			return nil, fmt.Errorf("GET dns-database/%s: cannot parse results: %w", name, err)
		}
		zones = []Zone{z}
	}
	if len(zones) != 1 {
		return nil, fmt.Errorf("GET dns-database/%s: got %d zones", name, len(zones))
	}
	z := zones[0]
	if z.Domain == "" {
		z.Domain = z.Name
	}
	return &z, nil
}

// PutEntries replaces the whole dns-entry table of a zone with entries.
// Other settings of the zone are left unchanged.
func (c *Client) PutEntries(ctx context.Context, name string, entries []Entry) error {
	if entries == nil {
		entries = []Entry{}
	}
	_, err := c.do(ctx, http.MethodPut, name, map[string]any{"dns-entry": entries})
	return err
}
