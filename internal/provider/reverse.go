package provider

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/fortigate"
)

// reversePrefix returns the address range covered by a reverse zone name
// (for example 12.10.in-addr.arpa). Zones that are not split on octet or nibble
// boundaries (RFC 2317 classless delegation) are not supported.
func reversePrefix(domain string) (netip.Prefix, error) {
	d := normName(domain)
	switch {
	case strings.HasSuffix(d, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(d, ".in-addr.arpa"), ".")
		if len(labels) < 1 || len(labels) > 3 {
			return netip.Prefix{}, fmt.Errorf("%s: in-addr.arpa zone must have 1 to 3 labels", domain)
		}
		var b [4]byte
		for i, l := range labels {
			n, err := strconv.Atoi(l)
			if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != l {
				return netip.Prefix{}, fmt.Errorf("%s: invalid octet %q", domain, l)
			}
			b[len(labels)-1-i] = byte(n)
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), 8*len(labels)), nil
	case strings.HasSuffix(d, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(d, ".ip6.arpa"), ".")
		if len(labels) < 1 || len(labels) > 31 {
			return netip.Prefix{}, fmt.Errorf("%s: ip6.arpa zone must have 1 to 31 labels", domain)
		}
		var b [16]byte
		for i, l := range labels {
			n, err := strconv.ParseUint(l, 16, 4)
			if err != nil || len(l) != 1 {
				return netip.Prefix{}, fmt.Errorf("%s: invalid nibble %q", domain, l)
			}
			pos := len(labels) - 1 - i // nibble position counted from the most significant
			if pos%2 == 0 {
				b[pos/2] |= byte(n) << 4
			} else {
				b[pos/2] |= byte(n)
			}
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), 4*len(labels)), nil
	}
	return netip.Prefix{}, fmt.Errorf("%s: not a reverse zone", domain)
}

// reverseEntries builds reverse entries from the forward A and AAAA records that fall
// within prefix. Preserved entries (anything other than PTR) are kept first, unchanged.
func reverseEntries(fwd recordSet, prefix netip.Prefix, preserved []fortigate.Entry) []fortigate.Entry {
	out := append([]fortigate.Entry(nil), preserved...)
	next := 1
	for _, e := range preserved {
		if e.ID >= next {
			next = e.ID + 1
		}
	}
	for _, k := range fwd.sortedKeys() {
		if k.typ != "A" && k.typ != "AAAA" {
			continue
		}
		r := fwd[k]
		for _, t := range sortedTargets(r.targets) {
			a, err := netip.ParseAddr(t)
			if err != nil || !prefix.Contains(a) {
				continue
			}
			e := fortigate.Entry{ID: next, Status: "enable", TTL: r.ttl, Hostname: k.name}
			if a.Is4() {
				e.Type, e.IP = "PTR", a.String()
			} else {
				e.Type, e.IPv6 = "PTR_V6", a.String()
			}
			out = append(out, e)
			next++
		}
	}
	return out
}

// preservedReverse returns the entries of a reverse zone that are not PTR records.
func preservedReverse(entries []fortigate.Entry) []fortigate.Entry {
	var preserved []fortigate.Entry
	for _, e := range entries {
		switch strings.ToUpper(e.Type) {
		case "PTR", "PTR_V6":
		default:
			preserved = append(preserved, e)
		}
	}
	return preserved
}
