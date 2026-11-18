package webhook

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/endpoint"
)

type fakeProvider struct{ got *endpoint.Changes }

func (f *fakeProvider) Domain() string { return "svc.technotut.net" }
func (f *fakeProvider) Records(context.Context) ([]*endpoint.Endpoint, error) {
	return []*endpoint.Endpoint{{DNSName: "a.svc.technotut.net", RecordType: "A", Targets: []string{"10.0.0.1"}}}, nil
}
func (f *fakeProvider) AdjustEndpoints(eps []*endpoint.Endpoint) []*endpoint.Endpoint { return eps }
func (f *fakeProvider) ApplyChanges(_ context.Context, ch *endpoint.Changes) error {
	f.got = ch
	return nil
}

func TestAPI(t *testing.T) {
	fp := &fakeProvider{}
	s := New(fp, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := s.APIHandler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("準備前の negotiate: %d", rec.Code)
	}
	s.SetReady(true)

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("Content-Type") != MediaType || strings.TrimSpace(rec.Body.String()) != `{"include":["svc.technotut.net"]}` {
		t.Fatalf("negotiate: %s %q", rec.Header().Get("Content-Type"), rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/records", nil))
	if !strings.Contains(rec.Body.String(), `"dnsName":"a.svc.technotut.net"`) {
		t.Fatalf("records: %s", rec.Body.String())
	}

	// external-dns の古い版は Create のように大文字で始まるフィールド名で送る。
	body := `{"Create":[{"dnsName":"b.svc.technotut.net","recordType":"A","targets":["10.0.0.2"]}],"updateNew":[],"Delete":null}`
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/records", strings.NewReader(body)))
	if rec.Code != http.StatusNoContent || fp.got == nil || len(fp.got.Create) != 1 || fp.got.Create[0].DNSName != "b.svc.technotut.net" {
		t.Fatalf("apply: %d %+v", rec.Code, fp.got)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/adjustendpoints", strings.NewReader(`[{"dnsName":"c.svc.technotut.net","recordType":"A","targets":["10.0.0.3"]}]`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "c.svc.technotut.net") {
		t.Fatalf("adjust: %d %s", rec.Code, rec.Body.String())
	}
}
