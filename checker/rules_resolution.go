package checker

import (
	"context"
	"fmt"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// resolutionRule flags nameservers whose host names could not be resolved
// to any IP address. An unresolvable NS is effectively dead weight in the
// delegation and is its own concern (distinct from any answer-posture check).
type resolutionRule struct{}

func (r *resolutionRule) Name() string { return "ns_resolution" }
func (r *resolutionRule) Description() string {
	return "Verifies that every nameserver host name declared in the delegation resolves to at least one IP address"
}

func (r *resolutionRule) Evaluate(ctx context.Context, obs sdk.ObservationGetter, _ sdk.CheckerOptions) []sdk.CheckState {
	report, errSt := loadReport(ctx, obs, "ns_resolution_error")
	if errSt != nil {
		return []sdk.CheckState{*errSt}
	}

	var out []sdk.CheckState
	for _, srv := range report.Servers {
		if srv.ResolutionError == "" {
			continue
		}
		out = append(out, sdk.CheckState{
			Status:  sdk.StatusCrit,
			Message: fmt.Sprintf("DNS resolution failed: %s", srv.ResolutionError),
			Code:    "ns_resolution_failed",
			Subject: srv.Name,
			Meta:    map[string]any{"name": srv.Name},
		})
	}

	if len(out) == 0 {
		return []sdk.CheckState{{
			Status:  sdk.StatusOK,
			Message: "every nameserver host name resolves to at least one IP address",
			Code:    "ns_resolution_ok",
		}}
	}
	return out
}
