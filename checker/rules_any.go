package checker

import (
	"context"
	"fmt"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// anyRFC8482Rule flags nameservers that return the full record set for a
// qtype=ANY query, instead of the minimal HINFO response recommended by
// RFC 8482.
type anyRFC8482Rule struct{}

func (r *anyRFC8482Rule) Name() string { return "ns_any_handled" }
func (r *anyRFC8482Rule) Description() string {
	return "Verifies that ANY queries are handled per RFC 8482 (HINFO or minimal answer)"
}

func (r *anyRFC8482Rule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, _ sdk.CheckerOptions) []sdk.CheckState {
	report, errSt := loadReport(ctx, obs, "ns_any_error")
	if errSt != nil {
		return []sdk.CheckState{*errSt}
	}

	servers := probedServers(report)
	if len(servers) == 0 {
		return []sdk.CheckState{noProbesState("ns_any_skipped")}
	}

	out := make([]sdk.CheckState, 0, len(servers))
	for _, srv := range servers {
		state := sdk.CheckState{
			Subject: serverLabel(srv),
			Meta:    serverMeta(srv),
		}
		switch {
		case srv.ANY.Error != "":
			state.Status = sdk.StatusUnknown
			state.Code = "ns_any_skipped"
			state.Message = fmt.Sprintf("query failed: %s", srv.ANY.Error)
		case srv.ANY.Rcode != "NOERROR":
			state.Status = sdk.StatusOK
			state.Code = "ns_any_ok"
			state.Message = fmt.Sprintf("ANY refused (rcode=%s)", srv.ANY.Rcode)
		case srv.ANY.HINFOOnly:
			state.Status = sdk.StatusOK
			state.Code = "ns_any_ok"
			state.Message = "RFC 8482 compliant HINFO response"
		case srv.ANY.AnswerCount == 0:
			state.Status = sdk.StatusOK
			state.Code = "ns_any_ok"
			state.Message = "ANY returned empty answer"
		default:
			state.Status = sdk.StatusWarn
			state.Code = "ns_any_non_compliant"
			state.Message = fmt.Sprintf("ANY returned %d records (not RFC 8482 compliant)", srv.ANY.AnswerCount)
		}
		out = append(out, state)
	}
	return out
}
