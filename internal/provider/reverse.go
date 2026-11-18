package provider

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/fortigate"
)

// reversePrefix は逆引きのゾーンの名前 (例: 12.10.in-addr.arpa) から、対応するアドレスの範囲を求める。
// オクテットやニブルの区切りでないゾーン (RFC 2317 の classless) は扱わない。
func reversePrefix(domain string) (netip.Prefix, error) {
	d := normName(domain)
	switch {
	case strings.HasSuffix(d, ".in-addr.arpa"):
		labels := strings.Split(strings.TrimSuffix(d, ".in-addr.arpa"), ".")
		if len(labels) < 1 || len(labels) > 3 {
			return netip.Prefix{}, fmt.Errorf("%s: in-addr.arpa のラベルは 1 から 3 個", domain)
		}
		var b [4]byte
		for i, l := range labels {
			n, err := strconv.Atoi(l)
			if err != nil || n < 0 || n > 255 || strconv.Itoa(n) != l {
				return netip.Prefix{}, fmt.Errorf("%s: オクテットが不正: %q", domain, l)
			}
			b[len(labels)-1-i] = byte(n)
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), 8*len(labels)), nil
	case strings.HasSuffix(d, ".ip6.arpa"):
		labels := strings.Split(strings.TrimSuffix(d, ".ip6.arpa"), ".")
		if len(labels) < 1 || len(labels) > 31 {
			return netip.Prefix{}, fmt.Errorf("%s: ip6.arpa のラベルは 1 から 31 個", domain)
		}
		var b [16]byte
		for i, l := range labels {
			n, err := strconv.ParseUint(l, 16, 4)
			if err != nil || len(l) != 1 {
				return netip.Prefix{}, fmt.Errorf("%s: ニブルが不正: %q", domain, l)
			}
			pos := len(labels) - 1 - i // 上位から何番目のニブルか
			if pos%2 == 0 {
				b[pos/2] |= byte(n) << 4
			} else {
				b[pos/2] |= byte(n)
			}
		}
		return netip.PrefixFrom(netip.AddrFrom16(b), 4*len(labels)), nil
	}
	return netip.Prefix{}, fmt.Errorf("%s: 逆引きのゾーンではない", domain)
}

// reverseEntries は、正引きの A と AAAA のうち prefix に入るものから、逆引きのエントリを作る。
// preserved (PTR 以外のエントリ) は先頭にそのまま残す。
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

// splitReverse は逆引きのゾーンのエントリを、PTR と それ以外 (preserved) に分ける。
func splitReverse(entries []fortigate.Entry) (ptr, preserved []fortigate.Entry) {
	for _, e := range entries {
		switch strings.ToUpper(e.Type) {
		case "PTR", "PTR_V6":
			ptr = append(ptr, e)
		default:
			preserved = append(preserved, e)
		}
	}
	return ptr, preserved
}
