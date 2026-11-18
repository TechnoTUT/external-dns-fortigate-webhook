package provider

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/endpoint"
	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/fortigate"
)

// 正引きのゾーンで webhook が扱うレコードの種類。
var managedTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

type key struct {
	name string // FQDN。小文字で末尾のドットなし
	typ  string
}

type record struct {
	targets map[string]struct{}
	ttl     int64
}

// recordSet は正引きのゾーンの、webhook が扱うレコードの集合。
type recordSet map[key]*record

func normName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// inZone は name が domain のサブドメイン (domain そのものは除く) かどうか。
func inZone(name, domain string) bool {
	return strings.HasSuffix(name, "."+domain) && len(name) > len(domain)+1
}

// normTarget はレコードの値を、FortiGate に書く形にそろえる。不正なら ok=false。
func normTarget(typ, t string) (string, bool) {
	switch typ {
	case "A":
		a, err := netip.ParseAddr(strings.TrimSpace(t))
		if err != nil || !a.Is4() {
			return "", false
		}
		return a.String(), true
	case "AAAA":
		a, err := netip.ParseAddr(strings.TrimSpace(t))
		if err != nil || !a.Is6() || a.Is4In6() {
			return "", false
		}
		return a.String(), true
	case "CNAME":
		n := normName(t)
		return n, n != ""
	}
	return "", false
}

// fromEntries は FortiGate のエントリを recordSet に変換する。
// 扱わないエントリ (NS や MX、無効にしたもの、ゾーンの頂点) は preserved に入れ、そのまま残す。
func fromEntries(domain string, entries []fortigate.Entry) (recordSet, []fortigate.Entry) {
	set := recordSet{}
	var preserved []fortigate.Entry
	for _, e := range entries {
		typ := strings.ToUpper(e.Type)
		h := strings.TrimSpace(e.Hostname)
		if !managedTypes[typ] || strings.EqualFold(e.Status, "disable") || h == "" || h == "@" {
			preserved = append(preserved, e)
			continue
		}
		var name string
		if strings.HasSuffix(h, ".") {
			name = normName(h)
		} else {
			name = normName(h + "." + domain)
		}
		var raw string
		switch typ {
		case "A":
			raw = e.IP
		case "AAAA":
			raw = e.IPv6
		case "CNAME":
			raw = e.CanonicalName
		}
		t, ok := normTarget(typ, raw)
		if !ok || !inZone(name, domain) {
			preserved = append(preserved, e)
			continue
		}
		k := key{name, typ}
		r := set[k]
		if r == nil {
			r = &record{targets: map[string]struct{}{}, ttl: e.TTL}
			set[k] = r
		}
		r.targets[t] = struct{}{}
	}
	return set, preserved
}

// endpoints は recordSet を ExternalDNS の Endpoint にする。
func (s recordSet) endpoints() []*endpoint.Endpoint {
	keys := s.sortedKeys()
	out := make([]*endpoint.Endpoint, 0, len(keys))
	for _, k := range keys {
		r := s[k]
		out = append(out, &endpoint.Endpoint{
			DNSName:    k.name,
			RecordType: k.typ,
			Targets:    sortedTargets(r.targets),
			RecordTTL:  r.ttl,
		})
	}
	return out
}

func (s recordSet) sortedKeys() []key {
	keys := make([]key, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		return keys[i].typ < keys[j].typ
	})
	return keys
}

func sortedTargets(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for t := range m {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// validate は Endpoint を webhook が扱えるかどうか確かめ、名前の正規化をした key を返す。
func validate(domain string, ep *endpoint.Endpoint) (key, error) {
	if ep == nil {
		return key{}, fmt.Errorf("空の endpoint")
	}
	k := key{normName(ep.DNSName), strings.ToUpper(ep.RecordType)}
	if !managedTypes[k.typ] {
		return k, fmt.Errorf("%s %s: 扱わない種類", k.name, k.typ)
	}
	if !inZone(k.name, domain) {
		return k, fmt.Errorf("%s %s: ゾーン %s の外か、ゾーンの頂点", k.name, k.typ, domain)
	}
	if ep.SetIdentifier != "" {
		return k, fmt.Errorf("%s %s: setIdentifier は扱えない", k.name, k.typ)
	}
	return k, nil
}

func (s recordSet) remove(k key, targets []string) {
	r := s[k]
	if r == nil {
		return
	}
	for _, t := range targets {
		if n, ok := normTarget(k.typ, t); ok {
			delete(r.targets, n)
		}
	}
	if len(r.targets) == 0 {
		delete(s, k)
	}
}

func (s recordSet) add(k key, targets []string, ttl int64) error {
	r := s[k]
	if r == nil {
		r = &record{targets: map[string]struct{}{}}
		s[k] = r
	}
	r.ttl = ttl
	for _, t := range targets {
		n, ok := normTarget(k.typ, t)
		if !ok {
			return fmt.Errorf("%s %s: 不正な値 %q", k.name, k.typ, t)
		}
		r.targets[n] = struct{}{}
	}
	if len(r.targets) == 0 {
		delete(s, k)
	}
	return nil
}

// toEntries は recordSet を FortiGate のエントリにする。preserved はそのままの ID で先頭に置き、
// webhook のエントリにはその後ろの ID を順に振る。
func (s recordSet) toEntries(domain string, preserved []fortigate.Entry) []fortigate.Entry {
	out := append([]fortigate.Entry(nil), preserved...)
	next := 1
	for _, e := range preserved {
		if e.ID >= next {
			next = e.ID + 1
		}
	}
	for _, k := range s.sortedKeys() {
		r := s[k]
		host := strings.TrimSuffix(k.name, "."+domain)
		for _, t := range sortedTargets(r.targets) {
			e := fortigate.Entry{ID: next, Status: "enable", Type: k.typ, TTL: r.ttl, Hostname: host}
			switch k.typ {
			case "A":
				e.IP = t
			case "AAAA":
				e.IPv6 = t
			case "CNAME":
				e.CanonicalName = t
			}
			out = append(out, e)
			next++
		}
	}
	return out
}

// sameEntries はエントリの並びが DNS の内容として同じかどうかを比べる。ID と並び順は見ない。
func sameEntries(a, b []fortigate.Entry) bool {
	if len(a) != len(b) {
		return false
	}
	ka, kb := entryKeys(a), entryKeys(b)
	for i := range ka {
		if ka[i] != kb[i] {
			return false
		}
	}
	return true
}

func entryKeys(es []fortigate.Entry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		typ := strings.ToUpper(e.Type)
		status := strings.ToLower(e.Status)
		if status == "" {
			status = "enable"
		}
		var v string
		switch typ {
		case "A":
			v = e.IP
		case "AAAA":
			v = canonIP(e.IPv6)
		case "CNAME":
			v = normName(e.CanonicalName)
		case "PTR":
			v = e.IP + " " + normName(e.Hostname)
		case "PTR_V6":
			v = canonIP(e.IPv6) + " " + normName(e.Hostname)
		default:
			v = fmt.Sprintf("%s %s %s %s %d", e.IP, canonIP(e.IPv6), normName(e.CanonicalName), normName(e.Hostname), e.Preference)
		}
		host := normName(e.Hostname)
		if typ == "PTR" || typ == "PTR_V6" {
			host = ""
		}
		out[i] = fmt.Sprintf("%s|%s|%s|%d|%s", typ, status, host, e.TTL, v)
	}
	sort.Strings(out)
	return out
}

func canonIP(s string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
		return a.String()
	}
	return s
}
