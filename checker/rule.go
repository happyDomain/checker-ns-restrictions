package checker

import (
	"context"
	"fmt"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Rules returns one CheckRule per individual NS security concern. Every rule
// reads the same shared observation produced by Collect and only looks at
// its own facet of the raw probe data, so a single network round trip feeds
// every rule.
func Rules() []sdk.CheckRule {
	return []sdk.CheckRule{
		&resolutionRule{},
		&axfrRule{},
		&ixfrRule{},
		&noRecursionRule{},
		&anyRFC8482Rule{},
		&authoritativeRule{},
	}
}

// loadReport fetches the shared NS observation. On error it returns a
// CheckState the caller should emit verbatim to short-circuit its rule.
func loadReport(ctx context.Context, obs sdk.ObservationGetter, errCode string) (*NSRestrictionsReport, *sdk.CheckState) {
	var report NSRestrictionsReport
	if err := obs.Get(ctx, ObservationKeyNSRestrictions, &report); err != nil {
		return nil, &sdk.CheckState{
			Status:  sdk.StatusError,
			Message: fmt.Sprintf("Failed to get NS restrictions data: %v", err),
			Code:    errCode,
		}
	}
	return &report, nil
}

// serverLabel returns a human-friendly subject for a given server result.
func serverLabel(srv NSServerResult) string {
	if srv.Address == "" {
		return srv.Name
	}
	return fmt.Sprintf("%s (%s)", srv.Name, srv.Address)
}

// serverMeta returns the per-server meta blob attached to every state a
// rule produces.
func serverMeta(srv NSServerResult) map[string]any {
	return map[string]any{
		"name":    srv.Name,
		"address": srv.Address,
	}
}

// probedServers returns only the servers that were actually probed
// (i.e. DNS-resolved and not skipped). Rules that need to iterate over
// probe results should call this helper to transparently skip the
// resolution-error and address-skipped rows, which are the concern of
// the dedicated resolutionRule.
func probedServers(report *NSRestrictionsReport) []NSServerResult {
	out := make([]NSServerResult, 0, len(report.Servers))
	for _, s := range report.Servers {
		if s.ResolutionError != "" || s.AddressSkipped {
			continue
		}
		out = append(out, s)
	}
	return out
}

// noProbesState returns the default state emitted when a rule has nothing to
// evaluate (no server was successfully probed).
func noProbesState(code string) sdk.CheckState {
	return sdk.CheckState{
		Status:  sdk.StatusUnknown,
		Message: "no nameserver could be probed",
		Code:    code,
	}
}
