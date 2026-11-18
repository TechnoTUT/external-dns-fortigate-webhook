package provider

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/endpoint"
	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/fortigate"
)

// Record types the webhook manages in the forward zone.
var managedTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true}

type key struct {
	name string // FQDN, lower case, without the trailing dot
	typ  string
}

type record struct {
	targets map[string]struct{}
	ttl     int64
}

// recordSet holds the records of the forward zone that the webhook manages.
type recordSet map[key]*record

func normName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// inZone reports whether name is a subdomain of domain (the domain itself excluded).
func inZone(name, domain string) bool {
	return strings.HasSuffix(name, "."+domain) && len(name) > len(domain)+1
}

// normTarget normalizes a record value to the form written to the FortiGate.
// ok is false when the value is invalid.
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

// fromEntries converts FortiGate entries into a recordSet.
// Entries the webhook does not manage (NS, MX, disabled entries, the zone apex) are
// returned in preserved and kept as they are.
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

// endpoints converts the recordSet into ExternalDNS endpoints.
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

// validate checks that the webhook can handle the endpoint and returns its normalized key.
func validate(domain string, ep *endpoint.Endpoint) (key, error) {
	if ep == nil {
		return key{}, fmt.Errorf("nil endpoint")
	}
	k := key{normName(ep.DNSName), strings.ToUpper(ep.RecordType)}
	if !managedTypes[k.typ] {
		return k, fmt.Errorf("%s %s: unsupported record type", k.name, k.typ)
	}
	if !inZone(k.name, domain) {
		return k, fmt.Errorf("%s %s: outside zone %s or at the zone apex", k.name, k.typ, domain)
	}
	if ep.SetIdentifier != "" {
		return k, fmt.Errorf("%s %s: setIdentifier is not supported", k.name, k.typ)
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
			return fmt.Errorf("%s %s: invalid target %q", k.name, k.typ, t)
		}
		r.targets[n] = struct{}{}
	}
	if len(r.targets) == 0 {
		delete(s, k)
	}
	return nil
}

// toEntries converts the recordSet into FortiGate entries. Preserved entries come first
// with their IDs unchanged, and the webhook's entries get the following IDs in order.
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
				// FortiOS appends the zone to a name without a trailing dot, so write an FQDN.
				e.CanonicalName = t + "."
			}
			out = append(out, e)
			next++
		}
	}
	return out
}

// sameEntries reports whether two entry lists have the same DNS content.
// IDs and order are ignored.
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
