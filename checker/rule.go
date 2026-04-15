package checker

import (
	"context"
	"fmt"
	"strings"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Rules returns one rule per individual NS security check. Every rule
// reads the same shared observation produced by Collect and only looks
// at its own check entry, so a single network round trip feeds all rules.
func Rules() []sdk.CheckRule {
	return []sdk.CheckRule{
		&singleCheckRule{
			ruleName:    "ns_axfr_refused",
			description: "Verifies that AXFR zone transfers are refused by every authoritative nameserver",
			checkName:   checkNameAXFR,
			failStatus:  sdk.StatusCrit,
			code:        "ns_axfr",
		},
		&singleCheckRule{
			ruleName:    "ns_ixfr_refused",
			description: "Verifies that IXFR zone transfers are refused by every authoritative nameserver",
			checkName:   checkNameIXFR,
			failStatus:  sdk.StatusWarn,
			code:        "ns_ixfr",
		},
		&singleCheckRule{
			ruleName:    "ns_no_recursion",
			description: "Verifies that authoritative nameservers do not advertise recursion (RA bit unset)",
			checkName:   checkNameNoRecursion,
			failStatus:  sdk.StatusWarn,
			code:        "ns_recursion",
		},
		&singleCheckRule{
			ruleName:    "ns_any_handled",
			description: "Verifies that ANY queries are handled per RFC 8482 (HINFO or minimal answer)",
			checkName:   checkNameANYHandled,
			failStatus:  sdk.StatusWarn,
			code:        "ns_any",
		},
		&singleCheckRule{
			ruleName:    "ns_is_authoritative",
			description: "Verifies that nameservers answer authoritatively (AA bit set) for the zone",
			checkName:   checkNameIsAuthoritative,
			failStatus:  sdk.StatusInfo,
			code:        "ns_authoritative",
		},
	}
}

// singleCheckRule evaluates one named check across all servers in the
// shared NSRestrictionsReport observation.
type singleCheckRule struct {
	ruleName    string
	description string
	checkName   string
	failStatus  sdk.Status
	code        string
}

func (r *singleCheckRule) Name() string        { return r.ruleName }
func (r *singleCheckRule) Description() string { return r.description }

func (r *singleCheckRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, opts sdk.CheckerOptions) sdk.CheckState {
	var report NSRestrictionsReport
	if err := obs.Get(ctx, ObservationKeyNSRestrictions, &report); err != nil {
		return sdk.CheckState{
			Status:  sdk.StatusError,
			Message: fmt.Sprintf("Failed to get NS restrictions data: %v", err),
			Code:    r.code + "_error",
		}
	}

	status := sdk.StatusOK
	var summaryParts []string
	failingServers := make([]map[string]string, 0)
	checked := false

	for _, srv := range report.Servers {
		item, found := findCheck(srv.Checks, r.checkName)
		if !found {
			// The collect step did not run this check on this server
			// (e.g. IPv6 unreachable, DNS resolution failure). Surface
			// the reason from whichever entry the server does have.
			if len(srv.Checks) > 0 {
				summaryParts = append(summaryParts, fmt.Sprintf("%s: skipped (%s)", serverLabel(srv), srv.Checks[0].Detail))
			} else {
				summaryParts = append(summaryParts, fmt.Sprintf("%s: skipped", serverLabel(srv)))
			}
			continue
		}

		checked = true

		if item.OK {
			summaryParts = append(summaryParts, fmt.Sprintf("%s: OK", serverLabel(srv)))
			continue
		}

		if status < r.failStatus {
			status = r.failStatus
		}
		summaryParts = append(summaryParts, fmt.Sprintf("%s: FAIL (%s)", serverLabel(srv), item.Detail))
		failingServers = append(failingServers, map[string]string{
			"name":    srv.Name,
			"address": srv.Address,
			"detail":  item.Detail,
		})
	}

	if !checked {
		status = sdk.StatusUnknown
	}

	return sdk.CheckState{
		Status:  status,
		Message: strings.Join(summaryParts, " | "),
		Code:    r.code + "_result",
		Meta: map[string]any{
			"check":           r.checkName,
			"failing_servers": failingServers,
		},
	}
}

func findCheck(items []NSCheckItem, name string) (NSCheckItem, bool) {
	for _, it := range items {
		if it.Name == name {
			return it, true
		}
	}
	return NSCheckItem{}, false
}

func serverLabel(srv NSServerResult) string {
	if srv.Address == "" {
		return srv.Name
	}
	return fmt.Sprintf("%s (%s)", srv.Name, srv.Address)
}
