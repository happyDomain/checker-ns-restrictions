package checker

import (
	"context"
	"fmt"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// noRecursionRule flags authoritative nameservers that still advertise
// recursion to the public (RA bit set), a classic open-resolver posture.
type noRecursionRule struct{}

func (r *noRecursionRule) Name() string { return "ns_no_recursion" }
func (r *noRecursionRule) Description() string {
	return "Verifies that authoritative nameservers do not advertise recursion (RA bit unset)"
}

func (r *noRecursionRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, _ sdk.CheckerOptions) []sdk.CheckState {
	report, errSt := loadReport(ctx, obs, "ns_recursion_error")
	if errSt != nil {
		return []sdk.CheckState{*errSt}
	}

	servers := probedServers(report)
	if len(servers) == 0 {
		return []sdk.CheckState{noProbesState("ns_recursion_skipped")}
	}

	out := make([]sdk.CheckState, 0, len(servers))
	for _, srv := range servers {
		state := sdk.CheckState{
			Subject: serverLabel(srv),
			Meta:    serverMeta(srv),
		}
		switch {
		case srv.SOA.Error != "":
			state.Status = sdk.StatusUnknown
			state.Code = "ns_recursion_skipped"
			state.Message = fmt.Sprintf("query failed: %s", srv.SOA.Error)
		case srv.SOA.RecursionAvailable:
			state.Status = sdk.StatusWarn
			state.Code = "ns_recursion_available"
			state.Message = "recursion available (RA bit set)"
		default:
			state.Status = sdk.StatusOK
			state.Code = "ns_recursion_ok"
			state.Message = "recursion not available"
		}
		out = append(out, state)
	}
	return out
}
