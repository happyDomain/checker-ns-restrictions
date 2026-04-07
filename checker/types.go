package checker

import "encoding/json"

// ObservationKeyNSRestrictions is the observation key for NS security
// restrictions data.
const ObservationKeyNSRestrictions = "ns_restrictions"

// NSRestrictionsReport contains the results of NS security restriction checks.
type NSRestrictionsReport struct {
	Servers []NSServerResult `json:"servers"`
}

// NSServerResult holds the check results for a single nameserver IP.
type NSServerResult struct {
	Name    string        `json:"name"`
	Address string        `json:"address"`
	Checks  []NSCheckItem `json:"checks"`
}

// NSCheckItem represents one security check for an NS server.
type NSCheckItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// serviceMessage is a minimal local copy of happydns.ServiceMessage matching
// the JSON wire shape, so this plugin does not depend on the happyDomain core
// repository.
type serviceMessage struct {
	Type    string          `json:"_svctype"`
	Domain  string          `json:"_domain"`
	Service json.RawMessage `json:"Service"`
}
