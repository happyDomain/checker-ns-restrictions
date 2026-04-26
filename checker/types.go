package checker

import "encoding/json"

// ObservationKeyNSRestrictions is the observation key for NS security
// restrictions data.
const ObservationKeyNSRestrictions = "ns_restrictions"

// NSRestrictionsReport contains the raw probe results from every discovered
// nameserver address. It carries facts (answer rcodes, flag bits, record
// counts, errors, …) and does not make any pass/fail judgment; rules derive
// status from these fields.
type NSRestrictionsReport struct {
	// Domain is the zone that was probed.
	Domain string `json:"domain"`

	// IPv6Reachable reflects whether the host running the checker could
	// reach the public IPv6 internet at collection time. When false,
	// probes against IPv6 addresses are skipped (AddressSkipped=true).
	IPv6Reachable bool `json:"ipv6Reachable"`

	// Servers holds one entry per (NS host, resolved address) pair,
	// plus one entry per NS host that failed DNS resolution (with
	// ResolutionError set and Address empty).
	Servers []NSServerResult `json:"servers"`
}

// NSServerResult holds raw probe results for a single nameserver address.
type NSServerResult struct {
	// Name is the authoritative NS host name being probed.
	Name string `json:"name"`

	// Address is the resolved IP address (may be empty when DNS
	// resolution failed or when the address was skipped).
	Address string `json:"address,omitempty"`

	// ResolutionError is set when resolving Name to any IP failed.
	// Other per-probe fields are not populated in that case.
	ResolutionError string `json:"resolutionError,omitempty"`

	// AddressSkipped is true when Address was not probed, e.g. an
	// IPv6 address on a host without IPv6 connectivity. Per-probe
	// fields are not populated.
	AddressSkipped bool `json:"addressSkipped,omitempty"`

	// SkipReason describes why AddressSkipped was set.
	SkipReason string `json:"skipReason,omitempty"`

	// AXFR carries the raw AXFR probe result.
	AXFR AXFRProbe `json:"axfr"`

	// IXFR carries the raw IXFR probe result.
	IXFR IXFRProbe `json:"ixfr"`

	// SOA carries the SOA/RD query used for the recursion and
	// authoritative probes.
	SOA SOAProbe `json:"soa"`

	// ANY carries the raw ANY-query probe result.
	ANY ANYProbe `json:"any"`
}

// AXFRProbe describes what happened when an AXFR zone transfer was attempted.
type AXFRProbe struct {
	// Accepted is true when the server served a full zone transfer
	// (emitted at least a SOA envelope).
	Accepted bool `json:"accepted"`
	// Reason is a human-readable description of the outcome when
	// Accepted is false: either the refusal reason returned by the
	// server or the transport error encountered. Empty when Accepted
	// is true.
	Reason string `json:"reason,omitempty"`
	// Cancelled is true when the probe was cut short by context cancel.
	Cancelled bool `json:"cancelled,omitempty"`
}

// IXFRProbe describes what happened when an IXFR query was issued.
type IXFRProbe struct {
	// Error is non-empty when the UDP query itself failed.
	Error string `json:"error,omitempty"`
	// Rcode is the DNS rcode string of the response ("" on error).
	Rcode string `json:"rcode,omitempty"`
	// AnswerCount is the number of answer records returned.
	AnswerCount int `json:"answerCount"`
}

// SOAProbe describes the SOA/RD=1 query used by the recursion and
// authoritative rules.
type SOAProbe struct {
	// Error is non-empty when the UDP query itself failed.
	Error string `json:"error,omitempty"`
	// RecursionAvailable reflects the RA bit in the response header.
	RecursionAvailable bool `json:"recursionAvailable"`
	// Authoritative reflects the AA bit in the response header.
	Authoritative bool `json:"authoritative"`
}

// ANYProbe describes the outcome of a qtype=ANY query, used to judge RFC
// 8482 compliance.
type ANYProbe struct {
	// Error is non-empty when the UDP query itself failed.
	Error string `json:"error,omitempty"`
	// Rcode is the DNS rcode string of the response ("" on error).
	Rcode string `json:"rcode,omitempty"`
	// AnswerCount is the number of answer records in the response.
	AnswerCount int `json:"answerCount"`
	// HINFOOnly is true when the answer section is exactly a single
	// HINFO record, i.e. the RFC 8482 minimal response.
	HINFOOnly bool `json:"hinfoOnly"`
}

// serviceMessage is a minimal local copy of happydns.ServiceMessage matching
// the JSON wire shape, so this plugin does not depend on the happyDomain core
// repository.
type serviceMessage struct {
	Type    string          `json:"_svctype"`
	Domain  string          `json:"_domain"`
	Service json.RawMessage `json:"Service"`
}
