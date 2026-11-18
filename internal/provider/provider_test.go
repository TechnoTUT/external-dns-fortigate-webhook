package provider

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"

	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/endpoint"
	"github.com/TechnoTUT/external-dns-fortigate-webhook/internal/fortigate"
)

type fakeAPI struct {
	zones map[string]*fortigate.Zone
	puts  map[string]int
}

func (f *fakeAPI) GetZone(_ context.Context, name string) (*fortigate.Zone, error) {
	z := *f.zones[name]
	z.Entries = append([]fortigate.Entry(nil), z.Entries...)
	return &z, nil
}

func (f *fakeAPI) PutEntries(_ context.Context, name string, entries []fortigate.Entry) error {
	f.zones[name].Entries = append([]fortigate.Entry(nil), entries...)
	f.puts[name]++
	return nil
}

func newFake() *fakeAPI {
	return &fakeAPI{
		puts: map[string]int{},
		zones: map[string]*fortigate.Zone{
			"svc.technotut.net": {Name: "svc.technotut.net", Domain: "svc.technotut.net", Entries: []fortigate.Entry{
				{ID: 1, Status: "enable", Type: "NS", Hostname: "@", CanonicalName: "ns1"},
				{ID: 5, Status: "enable", Type: "A", Hostname: "pa", IP: "192.168.12.22"},
			}},
			"rev10.12": {Name: "rev10.12", Domain: "12.10.in-addr.arpa", Entries: []fortigate.Entry{
				{ID: 1, Status: "enable", Type: "NS", Hostname: "@", CanonicalName: "ns1.svc.technotut.net"},
				{ID: 2, Status: "enable", Type: "PTR", IP: "10.12.9.9", Hostname: "stale.svc.technotut.net"},
			}},
		},
	}
}

func newProvider(t *testing.T, api ZoneAPI, rev ...string) *Provider {
	t.Helper()
	p := New(api, Config{ForwardZone: "svc.technotut.net", ReverseZones: rev}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRecords(t *testing.T) {
	p := newProvider(t, newFake())
	eps, err := p.Records(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []*endpoint.Endpoint{{DNSName: "pa.svc.technotut.net", RecordType: "A", Targets: []string{"192.168.12.22"}}}
	if !reflect.DeepEqual(eps, want) {
		t.Fatalf("got %+v", eps)
	}
}

func TestApplyChanges(t *testing.T) {
	f := newFake()
	p := newProvider(t, f, "rev10.12")
	ctx := context.Background()
	err := p.ApplyChanges(ctx, &endpoint.Changes{
		Create: []*endpoint.Endpoint{
			{DNSName: "cam1.svc.technotut.net", RecordType: "A", Targets: []string{"10.12.0.5"}},
			{DNSName: "www.svc.technotut.net", RecordType: "CNAME", Targets: []string{"cam1.svc.technotut.net."}},
			{DNSName: "outside.example.com", RecordType: "A", Targets: []string{"10.12.0.6"}},
		},
		UpdateOld: []*endpoint.Endpoint{{DNSName: "pa.svc.technotut.net", RecordType: "A", Targets: []string{"192.168.12.22"}}},
		UpdateNew: []*endpoint.Endpoint{{DNSName: "pa.svc.technotut.net", RecordType: "A", Targets: []string{"192.168.12.23"}, RecordTTL: 60}},
	})
	if err != nil {
		t.Fatal(err)
	}
	eps, _ := p.Records(ctx)
	want := []*endpoint.Endpoint{
		{DNSName: "cam1.svc.technotut.net", RecordType: "A", Targets: []string{"10.12.0.5"}},
		{DNSName: "pa.svc.technotut.net", RecordType: "A", Targets: []string{"192.168.12.23"}, RecordTTL: 60},
		{DNSName: "www.svc.technotut.net", RecordType: "CNAME", Targets: []string{"cam1.svc.technotut.net"}},
	}
	if !reflect.DeepEqual(eps, want) {
		t.Fatalf("got %+v", eps)
	}
	// NS (preserved) keeps its ID, and the webhook entries get the following IDs.
	fwd := f.zones["svc.technotut.net"].Entries
	if fwd[0].Type != "NS" || fwd[0].ID != 1 || fwd[1].ID != 2 || fwd[1].Hostname != "cam1" {
		t.Fatalf("forward entries: %+v", fwd)
	}
	for _, e := range fwd {
		if e.Type == "CNAME" && e.CanonicalName != "cam1.svc.technotut.net." {
			t.Fatalf("CNAME must be written as an FQDN with a trailing dot: %+v", e)
		}
	}
	// Reverse: only cam1 (in 10.12.0.0/16) becomes a PTR, the stale PTR is removed and NS is kept.
	rev := f.zones["rev10.12"].Entries
	if len(rev) != 2 || rev[0].Type != "NS" || rev[1].Type != "PTR" || rev[1].IP != "10.12.0.5" || rev[1].Hostname != "cam1.svc.technotut.net." {
		t.Fatalf("reverse entries: %+v", rev)
	}

	// Applying the same change again must not write.
	puts := f.puts["svc.technotut.net"]
	if err := p.ApplyChanges(ctx, &endpoint.Changes{Create: []*endpoint.Endpoint{{DNSName: "cam1.svc.technotut.net", RecordType: "A", Targets: []string{"10.12.0.5"}}}}); err != nil {
		t.Fatal(err)
	}
	if f.puts["svc.technotut.net"] != puts {
		t.Fatal("wrote although nothing changed")
	}

	// Delete
	if err := p.ApplyChanges(ctx, &endpoint.Changes{Delete: []*endpoint.Endpoint{{DNSName: "cam1.svc.technotut.net", RecordType: "A", Targets: []string{"10.12.0.5"}}}}); err != nil {
		t.Fatal(err)
	}
	if rev := f.zones["rev10.12"].Entries; len(rev) != 1 {
		t.Fatalf("PTR still present: %+v", rev)
	}
}

func TestDryRun(t *testing.T) {
	f := newFake()
	p := New(f, Config{ForwardZone: "svc.technotut.net", DryRun: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.ApplyChanges(context.Background(), &endpoint.Changes{Create: []*endpoint.Endpoint{{DNSName: "a.svc.technotut.net", RecordType: "A", Targets: []string{"10.0.0.1"}}}}); err != nil {
		t.Fatal(err)
	}
	if len(f.puts) != 0 {
		t.Fatal("wrote in dry-run mode")
	}
}

func TestAdjustEndpoints(t *testing.T) {
	p := newProvider(t, newFake())
	got := p.AdjustEndpoints([]*endpoint.Endpoint{
		{DNSName: "Cam1.SVC.technotut.net.", RecordType: "a", Targets: []string{"10.12.0.5", "bad"}, ProviderSpecific: []endpoint.ProviderSpecificProperty{{Name: "x", Value: "y"}}},
		{DNSName: "svc.technotut.net", RecordType: "A", Targets: []string{"10.0.0.1"}},
		{DNSName: "t.svc.technotut.net", RecordType: "TXT", Targets: []string{"x"}},
		{DNSName: "v6.svc.technotut.net", RecordType: "AAAA", Targets: []string{"2001:DB8::0001"}},
	})
	want := []*endpoint.Endpoint{
		{DNSName: "cam1.svc.technotut.net", RecordType: "A", Targets: []string{"10.12.0.5"}},
		{DNSName: "v6.svc.technotut.net", RecordType: "AAAA", Targets: []string{"2001:db8::1"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestReversePrefix(t *testing.T) {
	cases := map[string]string{
		"12.10.in-addr.arpa":               "10.12.0.0/16",
		"10.in-addr.arpa.":                 "10.0.0.0/8",
		"0.12.10.in-addr.arpa":             "10.12.0.0/24",
		"8.b.d.0.1.0.0.2.ip6.arpa":         "2001:db8::/32",
		"0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": "2001:db8::/48",
	}
	for in, want := range cases {
		got, err := reversePrefix(in)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got != netip.MustParsePrefix(want) {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
	for _, bad := range []string{"svc.technotut.net", "0-25.12.10.in-addr.arpa", "256.in-addr.arpa", "1.2.3.4.in-addr.arpa", "01.in-addr.arpa"} {
		if _, err := reversePrefix(bad); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
}
