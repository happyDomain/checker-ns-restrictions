package checker

import (
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Version is the checker version reported in CheckerDefinition.Version.
//
// It defaults to "built-in", which is appropriate when the checker package is
// imported directly. Standalone binaries and plugin entrypoints override this
// from their own Version variable at the start of main(), which makes it easy
// for CI to inject a version with a single -ldflags "-X main.Version=..."
// flag instead of targeting the nested package path.
var Version = "built-in"

// Definition returns the CheckerDefinition for the NS security restrictions
// checker.
func Definition() *sdk.CheckerDefinition {
	return &sdk.CheckerDefinition{
		ID:      "ns_restrictions",
		Name:    "NS Security Restrictions",
		Version: Version,
		Availability: sdk.CheckerAvailability{
			ApplyToService:  true,
			LimitToServices: []string{serviceTypeOrigin, serviceTypeNSOnlyOrigin},
		},
		ObservationKeys: []sdk.ObservationKey{ObservationKeyNSRestrictions},
		Options: sdk.CheckerOptionsDocumentation{
			ServiceOpts: []sdk.CheckerOptionDocumentation{
				{
					Id:       "service",
					Label:    "Service",
					AutoFill: sdk.AutoFillService,
				},
				{
					Id:       "domainName",
					Label:    "Domain name",
					AutoFill: sdk.AutoFillDomainName,
				},
			},
		},
		Rules: Rules(),
		Interval: &sdk.CheckIntervalSpec{
			Min:     1 * time.Hour,
			Max:     24 * time.Hour,
			Default: 6 * time.Hour,
		},
	}
}
