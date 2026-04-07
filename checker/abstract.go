package checker

import (
	"encoding/json"

	"github.com/miekg/dns"
)

// Service type identifiers as exposed by happyDomain core.
const (
	serviceTypeOrigin       = "abstract.Origin"
	serviceTypeNSOnlyOrigin = "abstract.NSOnlyOrigin"
)

// originPayload is a minimal local copy of services/abstract.Origin keeping
// only the field this checker reads. The JSON tag matches the upstream wire
// format ("ns").
type originPayload struct {
	NameServers []*dns.NS `json:"ns"`
}

// nsOnlyOriginPayload is a minimal local copy of
// services/abstract.NSOnlyOrigin keeping only the field this checker reads.
type nsOnlyOriginPayload struct {
	NameServers []*dns.NS `json:"ns"`
}

// nsFromService extracts the list of NS records from an Origin or
// NSOnlyOrigin service payload.
func nsFromService(svc *serviceMessage) []*dns.NS {
	switch svc.Type {
	case serviceTypeOrigin:
		var o originPayload
		if err := json.Unmarshal(svc.Service, &o); err != nil {
			return nil
		}
		return o.NameServers
	case serviceTypeNSOnlyOrigin:
		var o nsOnlyOriginPayload
		if err := json.Unmarshal(svc.Service, &o); err != nil {
			return nil
		}
		return o.NameServers
	}
	return nil
}
