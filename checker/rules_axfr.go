package checker

import (
	"context"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// axfrRule flags nameservers that accept full AXFR zone transfers from
// arbitrary clients, which leaks the entire zone content.
type axfrRule struct{}

func (r *axfrRule) Name() string { return "ns_axfr_refused" }
func (r *axfrRule) Description() string {
	return "Verifies that AXFR zone transfers are refused by every authoritative nameserver"
}

func (r *axfrRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, _ sdk.CheckerOptions) []sdk.CheckState {
	report, errSt := loadReport(ctx, obs, "ns_axfr_error")
	if errSt != nil {
		return []sdk.CheckState{*errSt}
	}

	servers := probedServers(report)
	if len(servers) == 0 {
		return []sdk.CheckState{noProbesState("ns_axfr_skipped")}
	}

	out := make([]sdk.CheckState, 0, len(servers))
	for _, srv := range servers {
		state := sdk.CheckState{
			Subject: serverLabel(srv),
			Meta:    serverMeta(srv),
		}
		if srv.AXFR.Cancelled {
			state.Status = sdk.StatusUnknown
			state.Code = "ns_axfr_skipped"
			state.Message = srv.AXFR.Reason
		} else if srv.AXFR.Accepted {
			state.Status = sdk.StatusCrit
			state.Code = "ns_axfr_accepted"
			state.Message = "AXFR zone transfer accepted"
		} else {
			state.Status = sdk.StatusOK
			state.Code = "ns_axfr_ok"
			state.Message = srv.AXFR.Reason
			if state.Message == "" {
				state.Message = "AXFR refused"
			}
		}
		out = append(out, state)
	}
	return out
}
