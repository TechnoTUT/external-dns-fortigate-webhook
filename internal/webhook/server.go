// Package webhook serves the ExternalDNS webhook API (version 1).
// https://kubernetes-sigs.github.io/external-dns/latest/docs/tutorials/webhook-provider/
package webhook

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/endpoint"
)

// MediaType is the Content-Type of the webhook API.
const MediaType = "application/external.dns.webhook+json;version=1"

// Provider is the provider called by the webhook.
type Provider interface {
	Domain() string
	Records(ctx context.Context) ([]*endpoint.Endpoint, error)
	AdjustEndpoints(eps []*endpoint.Endpoint) []*endpoint.Endpoint
	ApplyChanges(ctx context.Context, ch *endpoint.Changes) error
}

// Server holds the HTTP handlers for the webhook API and the health checks.
type Server struct {
	p     Provider
	log   *slog.Logger
	ready atomic.Bool
}

// New creates a Server.
func New(p Provider, log *slog.Logger) *Server {
	return &Server{p: p, log: log}
}

// SetReady sets the state reported by /readyz.
func (s *Server) SetReady(v bool) { s.ready.Store(v) }

// APIHandler is the API called by ExternalDNS. Serve it on localhost only.
func (s *Server) APIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.negotiate)
	mux.HandleFunc("GET /records", s.records)
	mux.HandleFunc("POST /records", s.applyChanges)
	mux.HandleFunc("POST /adjustendpoints", s.adjustEndpoints)
	return mux
}

// HealthHandler serves the health checks called by the kubelet.
func (s *Server) HealthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", MediaType)
	w.Header().Set("Vary", "Content-Type")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.log.Error("cannot write response", "err", err)
	}
}

func (s *Server) negotiate(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	s.writeJSON(w, endpoint.DomainFilter{Include: []string{s.p.Domain()}})
}

func (s *Server) records(w http.ResponseWriter, r *http.Request) {
	eps, err := s.p.Records(r.Context())
	if err != nil {
		s.log.Error("cannot read records", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, eps)
}

func (s *Server) applyChanges(w http.ResponseWriter, r *http.Request) {
	var ch endpoint.Changes
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&ch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.log.Info("changes received", "create", len(ch.Create), "updateOld", len(ch.UpdateOld), "updateNew", len(ch.UpdateNew), "delete", len(ch.Delete))
	if err := s.p.ApplyChanges(r.Context(), &ch); err != nil {
		s.log.Error("cannot apply changes", "err", err)
		// ExternalDNS retries a 5xx on the next sync.
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adjustEndpoints(w http.ResponseWriter, r *http.Request) {
	var eps []*endpoint.Endpoint
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&eps); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.writeJSON(w, s.p.AdjustEndpoints(eps))
}
