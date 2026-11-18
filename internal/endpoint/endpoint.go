// Package endpoint defines the types exchanged over the ExternalDNS webhook API (version 1).
// They match the JSON of endpoint.Endpoint and plan.Changes in sigs.k8s.io/external-dns.
// The external-dns module itself is not imported because of its large dependency tree.
package endpoint

// ProviderSpecificProperty is a provider-specific setting. This webhook does not use any.
type ProviderSpecificProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Endpoint is a record set for one name and type.
type Endpoint struct {
	DNSName          string                     `json:"dnsName,omitempty"`
	Targets          []string                   `json:"targets,omitempty"`
	RecordType       string                     `json:"recordType,omitempty"`
	SetIdentifier    string                     `json:"setIdentifier,omitempty"`
	RecordTTL        int64                      `json:"recordTTL,omitempty"`
	Labels           map[string]string          `json:"labels,omitempty"`
	ProviderSpecific []ProviderSpecificProperty `json:"providerSpecific,omitempty"`
}

// Changes is the change set received by ApplyChanges.
// The case of the field names differs between external-dns versions, but encoding/json
// matches field names case-insensitively.
type Changes struct {
	Create    []*Endpoint `json:"create,omitempty"`
	UpdateOld []*Endpoint `json:"updateOld,omitempty"`
	UpdateNew []*Endpoint `json:"updateNew,omitempty"`
	Delete    []*Endpoint `json:"delete,omitempty"`
}

// DomainFilter is returned by Negotiate and lists the domains the webhook handles.
type DomainFilter struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}
