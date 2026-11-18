package fortigate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetAndPut(t *testing.T) {
	var gotPut map[string][]Entry
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.EscapedPath() != "/api/v2/cmdb/system/dns-database/svc.technotut.net" || r.URL.Query().Get("vdom") != "root" {
			t.Errorf("path %s query %s", r.URL.EscapedPath(), r.URL.RawQuery)
		}
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"http_method":"GET","results":[{"name":"svc.technotut.net","domain":"svc.technotut.net","dns-entry":[{"id":1,"status":"enable","type":"A","ttl":0,"ip":"192.168.98.2","ipv6":"::","hostname":"drive","canonical-name":""}]}],"status":"success","http_status":200}`))
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&gotPut)
			_, _ = w.Write([]byte(`{"http_method":"PUT","status":"success","http_status":200}`))
		}
	}))
	defer srv.Close()

	c, err := New(Config{BaseURL: srv.URL, Token: "secret", VDOM: "root"})
	if err != nil {
		t.Fatal(err)
	}
	z, err := c.GetZone(context.Background(), "svc.technotut.net")
	if err != nil {
		t.Fatal(err)
	}
	if z.Domain != "svc.technotut.net" || len(z.Entries) != 1 || z.Entries[0].Hostname != "drive" || z.Entries[0].IP != "192.168.98.2" {
		t.Fatalf("got %+v", z)
	}
	if err := c.PutEntries(context.Background(), "svc.technotut.net", nil); err != nil {
		t.Fatal(err)
	}
	if e, ok := gotPut["dns-entry"]; !ok || len(e) != 0 {
		t.Fatalf("PUT body %+v", gotPut)
	}
}

func TestTokenInQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.URL.Query().Get("access_token") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"name":"z","domain":"","dns-entry":[]}],"status":"success"}`))
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Token: "secret", TokenInQuery: true})
	z, err := c.GetZone(context.Background(), "z")
	if err != nil {
		t.Fatal(err)
	}
	if z.Domain != "z" {
		t.Fatalf("domain not filled from name: %+v", z)
	}
}

func TestAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"status":"error","http_status":500,"error":-651,"cli_error":"invalid hostname"}`))
	}))
	defer srv.Close()
	c, _ := New(Config{BaseURL: srv.URL, Token: "secret", TokenInQuery: true})
	err := c.PutEntries(context.Background(), "z", nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != -651 || ae.Message != "invalid hostname" {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("error message contains the token")
	}
}
