// Package provider applies ExternalDNS changes to a FortiGate dns-database.
//
// Both the forward zone and the reverse zones must be dedicated to the webhook.
// A FortiGate dns-entry cannot hold TXT records, so the ExternalDNS TXT registry
// (which records record ownership) cannot be used. Every A, AAAA and CNAME entry in the
// forward zone, and every PTR entry in a reverse zone, is treated as owned by the webhook.
package provider

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/endpoint"
	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/fortigate"
)

// ZoneAPI reads and writes FortiGate zones. Tests replace it with a fake.
type ZoneAPI interface {
	GetZone(ctx context.Context, name string) (*fortigate.Zone, error)
	PutEntries(ctx context.Context, name string, entries []fortigate.Entry) error
}

// Config configures a Provider.
type Config struct {
	ForwardZone  string   // name of the forward zone in dns-database
	ReverseZones []string // names of the reverse zones in dns-database; no PTR records when empty
	DryRun       bool     // log the entries instead of writing them to the FortiGate
}

type reverseZone struct {
	name   string
	prefix netip.Prefix
}

// Provider is the ExternalDNS provider.
type Provider struct {
	api     ZoneAPI
	cfg     Config
	log     *slog.Logger
	mu      sync.Mutex
	domain  string
	reverse []reverseZone
}

// New creates a Provider. It cannot be used until Init succeeds.
func New(api ZoneAPI, cfg Config, log *slog.Logger) *Provider {
	return &Provider{api: api, cfg: cfg, log: log}
}

// Init reads the zone domains from the FortiGate and validates the configuration.
func (p *Provider) Init(ctx context.Context) error {
	z, err := p.api.GetZone(ctx, p.cfg.ForwardZone)
	if err != nil {
		return fmt.Errorf("forward zone %s: %w", p.cfg.ForwardZone, err)
	}
	domain := normName(z.Domain)
	var rev []reverseZone
	for _, name := range p.cfg.ReverseZones {
		rz, err := p.api.GetZone(ctx, name)
		if err != nil {
			return fmt.Errorf("reverse zone %s: %w", name, err)
		}
		prefix, err := reversePrefix(rz.Domain)
		if err != nil {
			return fmt.Errorf("reverse zone %s: %w", name, err)
		}
		rev = append(rev, reverseZone{name: name, prefix: prefix})
	}
	p.mu.Lock()
	p.domain, p.reverse = domain, rev
	p.mu.Unlock()
	p.log.Info("zones loaded", "forward", p.cfg.ForwardZone, "domain", domain, "reverse", len(rev), "dryRun", p.cfg.DryRun)
	return nil
}

// Domain returns the domain of the forward zone.
func (p *Provider) Domain() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.domain
}

// Records returns the records in the forward zone that the webhook manages.
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	domain := p.Domain()
	z, err := p.api.GetZone(ctx, p.cfg.ForwardZone)
	if err != nil {
		return nil, err
	}
	set, _ := fromEntries(domain, z.Entries)
	return set.endpoints(), nil
}

// AdjustEndpoints drops endpoints the webhook cannot handle and normalizes names and
// targets to the form Records returns. Without this, ExternalDNS would see a difference
// on every sync and keep updating the same records.
func (p *Provider) AdjustEndpoints(eps []*endpoint.Endpoint) []*endpoint.Endpoint {
	domain := p.Domain()
	out := make([]*endpoint.Endpoint, 0, len(eps))
	for _, ep := range eps {
		k, err := validate(domain, ep)
		if err != nil {
			p.log.Warn("dropping endpoint", "reason", err.Error())
			continue
		}
		targets := make(map[string]struct{}, len(ep.Targets))
		for _, t := range ep.Targets {
			n, ok := normTarget(k.typ, t)
			if !ok {
				p.log.Warn("dropping invalid target", "name", k.name, "type", k.typ, "target", t)
				continue
			}
			targets[n] = struct{}{}
		}
		if len(targets) == 0 {
			continue
		}
		if k.typ == "CNAME" && len(targets) > 1 {
			p.log.Warn("dropping CNAME with multiple targets", "name", k.name)
			continue
		}
		adj := *ep
		adj.DNSName = k.name
		adj.RecordType = k.typ
		adj.Targets = sortedTargets(targets)
		adj.ProviderSpecific = nil
		out = append(out, &adj)
	}
	return out
}

// ApplyChanges applies the changes to the forward zone and rebuilds the reverse zones.
func (p *Provider) ApplyChanges(ctx context.Context, ch *endpoint.Changes) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	z, err := p.api.GetZone(ctx, p.cfg.ForwardZone)
	if err != nil {
		return err
	}
	set, preserved := fromEntries(p.domain, z.Entries)

	// Apply Delete and UpdateOld first, then Create and UpdateNew.
	for _, ep := range ch.Delete {
		if k, err := validate(p.domain, ep); err == nil {
			set.remove(k, ep.Targets)
		} else {
			p.log.Warn("skipping delete", "reason", err.Error())
		}
	}
	for _, ep := range ch.UpdateOld {
		if k, err := validate(p.domain, ep); err == nil {
			set.remove(k, ep.Targets)
		}
	}
	for _, eps := range [][]*endpoint.Endpoint{ch.Create, ch.UpdateNew} {
		for _, ep := range eps {
			k, err := validate(p.domain, ep)
			if err != nil {
				p.log.Warn("skipping create", "reason", err.Error())
				continue
			}
			if err := set.add(k, ep.Targets, ep.RecordTTL); err != nil {
				return err
			}
		}
	}

	desired := set.toEntries(p.domain, preserved)
	if err := p.write(ctx, p.cfg.ForwardZone, z.Entries, desired); err != nil {
		return err
	}
	return p.syncReverse(ctx, set)
}

// SyncReverse reads the forward zone and rebuilds the reverse zones. It is called
// periodically to repair the reverse zones when only their write failed in ApplyChanges.
func (p *Provider) SyncReverse(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.reverse) == 0 {
		return nil
	}
	z, err := p.api.GetZone(ctx, p.cfg.ForwardZone)
	if err != nil {
		return err
	}
	set, _ := fromEntries(p.domain, z.Entries)
	return p.syncReverse(ctx, set)
}

func (p *Provider) syncReverse(ctx context.Context, fwd recordSet) error {
	var errs []error
	for _, rz := range p.reverse {
		z, err := p.api.GetZone(ctx, rz.name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		desired := reverseEntries(fwd, rz.prefix, preservedReverse(z.Entries))
		if err := p.write(ctx, rz.name, z.Entries, desired); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cannot update reverse zones: %v", errs)
	}
	return nil
}

func (p *Provider) write(ctx context.Context, zone string, current, desired []fortigate.Entry) error {
	if sameEntries(current, desired) {
		p.log.Debug("no changes", "zone", zone)
		return nil
	}
	if p.cfg.DryRun {
		p.log.Info("dry run: not writing", "zone", zone, "current", len(current), "desired", len(desired), "entries", desired)
		return nil
	}
	if err := p.api.PutEntries(ctx, zone, desired); err != nil {
		return err
	}
	p.log.Info("zone updated", "zone", zone, "before", len(current), "after", len(desired))
	return nil
}
