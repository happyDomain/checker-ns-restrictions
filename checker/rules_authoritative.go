package checker

import (
	"context"
	"fmt"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// authoritativeRule flags nameservers that answer the zone's SOA without
// setting the AA bit, i.e. they are not authoritative for the zone they
// are delegated to serve.
type authoritativeRule struct{}

func (r *authoritativeRule) Name() string { return "ns_is_authoritative" }
func (r *authoritativeRule) Description() string {
	return "Verifies that nameservers answer authoritatively (AA bit set) for the zone"
}

func (r *authoritativeRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, _ sdk.CheckerOptions) []sdk.CheckState {
	report, errSt := loadReport(ctx, obs, "ns_authoritative_error")
	if errSt != nil {
		return []sdk.CheckState{*errSt}
	}

	servers := probedServers(report)
	if len(servers) == 0 {
		return []sdk.CheckState{noProbesState("ns_authoritative_skipped")}
	}

	out := make([]sdk.CheckState, 0, len(servers))
	for _, srv := range servers {
		state := sdk.CheckState{
			Subject: serverLabel(srv),
			Meta:    serverMeta(srv),
		}
		switch {
		case srv.SOA.Error != "":
			state.Status = sdk.StatusInfo
			state.Code = "ns_authoritative_unknown"
			state.Message = fmt.Sprintf("query failed: %s", srv.SOA.Error)
		case srv.SOA.Authoritative:
			state.Status = sdk.StatusOK
			state.Code = "ns_authoritative_ok"
			state.Message = "server is authoritative (AA bit set)"
		default:
			state.Status = sdk.StatusInfo
			state.Code = "ns_authoritative_missing"
			state.Message = "server is not authoritative (AA bit not set)"
		}
		out = append(out, state)
	}
	return out
}
