package checker

import (
	"context"
	"fmt"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// ixfrRule flags nameservers that answer IXFR queries with records, which
// leaks incremental zone content to arbitrary clients.
type ixfrRule struct{}

func (r *ixfrRule) Name() string { return "ns_ixfr_refused" }
func (r *ixfrRule) Description() string {
	return "Verifies that IXFR zone transfers are refused by every authoritative nameserver"
}

func (r *ixfrRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, _ sdk.CheckerOptions) []sdk.CheckState {
	report, errSt := loadReport(ctx, obs, "ns_ixfr_error")
	if errSt != nil {
		return []sdk.CheckState{*errSt}
	}

	servers := probedServers(report)
	if len(servers) == 0 {
		return []sdk.CheckState{noProbesState("ns_ixfr_skipped")}
	}

	out := make([]sdk.CheckState, 0, len(servers))
	for _, srv := range servers {
		state := sdk.CheckState{
			Subject: serverLabel(srv),
			Meta:    serverMeta(srv),
		}
		switch {
		case srv.IXFR.Error != "":
			state.Status = sdk.StatusOK
			state.Code = "ns_ixfr_ok"
			state.Message = fmt.Sprintf("query failed: %s", srv.IXFR.Error)
		case srv.IXFR.Rcode != "NOERROR":
			state.Status = sdk.StatusOK
			state.Code = "ns_ixfr_ok"
			state.Message = fmt.Sprintf("IXFR refused (rcode=%s)", srv.IXFR.Rcode)
		case srv.IXFR.AnswerCount > 0:
			state.Status = sdk.StatusWarn
			state.Code = "ns_ixfr_accepted"
			state.Message = fmt.Sprintf("IXFR accepted with %d answer(s)", srv.IXFR.AnswerCount)
		default:
			state.Status = sdk.StatusOK
			state.Code = "ns_ixfr_ok"
			state.Message = "IXFR refused or empty"
		}
		out = append(out, state)
	}
	return out
}
