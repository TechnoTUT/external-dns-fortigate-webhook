// Package endpoint は ExternalDNS の webhook API (version=1) でやりとりする型。
// sigs.k8s.io/external-dns の endpoint.Endpoint と plan.Changes の JSON に合わせる。
// external-dns 本体のモジュールは依存が大きいので取り込まない。
package endpoint

// ProviderSpecificProperty は provider 固有の設定。この webhook では使わない。
type ProviderSpecificProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Endpoint は 1 つの名前と種類のレコード。
type Endpoint struct {
	DNSName          string                     `json:"dnsName,omitempty"`
	Targets          []string                   `json:"targets,omitempty"`
	RecordType       string                     `json:"recordType,omitempty"`
	SetIdentifier    string                     `json:"setIdentifier,omitempty"`
	RecordTTL        int64                      `json:"recordTTL,omitempty"`
	Labels           map[string]string          `json:"labels,omitempty"`
	ProviderSpecific []ProviderSpecificProperty `json:"providerSpecific,omitempty"`
}

// Changes は ApplyChanges で受け取る変更。
// external-dns の版によってフィールド名の大文字小文字が違うが、encoding/json は大文字小文字を区別しないで対応付ける。
type Changes struct {
	Create    []*Endpoint `json:"create,omitempty"`
	UpdateOld []*Endpoint `json:"updateOld,omitempty"`
	UpdateNew []*Endpoint `json:"updateNew,omitempty"`
	Delete    []*Endpoint `json:"delete,omitempty"`
}

// DomainFilter は Negotiate で返す、扱うドメイン。
type DomainFilter struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}
