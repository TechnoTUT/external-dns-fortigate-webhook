// Package provider は ExternalDNS の変更を FortiGate の dns-database に反映する。
//
// 正引きのゾーンと逆引きのゾーンは、どちらも webhook 専用であることを前提にする。
// FortiGate の dns-entry には TXT が置けず、ExternalDNS の所有者の記録 (TXT registry) が使えないため。
// ゾーンの A、AAAA、CNAME (逆引きのゾーンでは PTR) は、すべて webhook のものとして扱う。
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

// ZoneAPI は FortiGate のゾーンの読み書き。テストで差し替える。
type ZoneAPI interface {
	GetZone(ctx context.Context, name string) (*fortigate.Zone, error)
	PutEntries(ctx context.Context, name string, entries []fortigate.Entry) error
}

// Config は Provider の設定。
type Config struct {
	ForwardZone  string   // 正引きのゾーン (dns-database の名前)
	ReverseZones []string // 逆引きのゾーン (dns-database の名前)。空なら PTR を作らない
	DryRun       bool     // true なら FortiGate に書かず、書く内容をログに出す
}

type reverseZone struct {
	name   string
	prefix netip.Prefix
}

// Provider は ExternalDNS の provider。
type Provider struct {
	api     ZoneAPI
	cfg     Config
	log     *slog.Logger
	mu      sync.Mutex
	domain  string
	reverse []reverseZone
}

// New は Provider を作る。Init を呼ぶまで使えない。
func New(api ZoneAPI, cfg Config, log *slog.Logger) *Provider {
	return &Provider{api: api, cfg: cfg, log: log}
}

// Init は FortiGate からゾーンのドメインを読み、設定を確かめる。
func (p *Provider) Init(ctx context.Context) error {
	z, err := p.api.GetZone(ctx, p.cfg.ForwardZone)
	if err != nil {
		return fmt.Errorf("正引きのゾーン %s: %w", p.cfg.ForwardZone, err)
	}
	domain := normName(z.Domain)
	var rev []reverseZone
	for _, name := range p.cfg.ReverseZones {
		rz, err := p.api.GetZone(ctx, name)
		if err != nil {
			return fmt.Errorf("逆引きのゾーン %s: %w", name, err)
		}
		prefix, err := reversePrefix(rz.Domain)
		if err != nil {
			return fmt.Errorf("逆引きのゾーン %s: %w", name, err)
		}
		rev = append(rev, reverseZone{name: name, prefix: prefix})
	}
	p.mu.Lock()
	p.domain, p.reverse = domain, rev
	p.mu.Unlock()
	p.log.Info("ゾーンを読んだ", "forward", p.cfg.ForwardZone, "domain", domain, "reverse", len(rev), "dryRun", p.cfg.DryRun)
	return nil
}

// Domain は正引きのゾーンのドメイン。
func (p *Provider) Domain() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.domain
}

// Records は正引きのゾーンにある、webhook が扱うレコードを返す。
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	domain := p.Domain()
	z, err := p.api.GetZone(ctx, p.cfg.ForwardZone)
	if err != nil {
		return nil, err
	}
	set, _ := fromEntries(domain, z.Entries)
	return set.endpoints(), nil
}

// AdjustEndpoints は、扱えない endpoint を除き、名前と値を FortiGate から読み返したときと同じ形にそろえる。
// そろえないと、ExternalDNS が毎回差分があると判断して更新を繰り返す。
func (p *Provider) AdjustEndpoints(eps []*endpoint.Endpoint) []*endpoint.Endpoint {
	domain := p.Domain()
	out := make([]*endpoint.Endpoint, 0, len(eps))
	for _, ep := range eps {
		k, err := validate(domain, ep)
		if err != nil {
			p.log.Warn("endpoint を除く", "reason", err.Error())
			continue
		}
		targets := make(map[string]struct{}, len(ep.Targets))
		for _, t := range ep.Targets {
			n, ok := normTarget(k.typ, t)
			if !ok {
				p.log.Warn("不正な値を除く", "name", k.name, "type", k.typ, "target", t)
				continue
			}
			targets[n] = struct{}{}
		}
		if len(targets) == 0 {
			continue
		}
		if k.typ == "CNAME" && len(targets) > 1 {
			p.log.Warn("CNAME の値が複数あるので除く", "name", k.name)
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

// ApplyChanges は変更を正引きのゾーンに当て、逆引きのゾーンを作り直す。
func (p *Provider) ApplyChanges(ctx context.Context, ch *endpoint.Changes) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	z, err := p.api.GetZone(ctx, p.cfg.ForwardZone)
	if err != nil {
		return err
	}
	set, preserved := fromEntries(p.domain, z.Entries)

	// Delete、UpdateOld を先に当ててから Create、UpdateNew を当てる。
	for _, ep := range ch.Delete {
		if k, err := validate(p.domain, ep); err == nil {
			set.remove(k, ep.Targets)
		} else {
			p.log.Warn("削除を飛ばす", "reason", err.Error())
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
				p.log.Warn("追加を飛ばす", "reason", err.Error())
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

// SyncReverse は正引きのゾーンを読み、逆引きのゾーンを作り直す。
// ApplyChanges のあとに逆引きの書き込みだけ失敗した場合に、定期的に呼んで直す。
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
		_, preserved := splitReverse(z.Entries)
		desired := reverseEntries(fwd, rz.prefix, preserved)
		if err := p.write(ctx, rz.name, z.Entries, desired); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("逆引きのゾーンを更新できない: %v", errs)
	}
	return nil
}

func (p *Provider) write(ctx context.Context, zone string, current, desired []fortigate.Entry) error {
	if sameEntries(current, desired) {
		p.log.Debug("変更なし", "zone", zone)
		return nil
	}
	if p.cfg.DryRun {
		p.log.Info("dry-run: 書き込まない", "zone", zone, "current", len(current), "desired", len(desired), "entries", desired)
		return nil
	}
	if err := p.api.PutEntries(ctx, zone, desired); err != nil {
		return err
	}
	p.log.Info("ゾーンを更新した", "zone", zone, "before", len(current), "after", len(desired))
	return nil
}
