package checker

import (
	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Provider returns a new NS restrictions observation provider.
func Provider() sdk.ObservationProvider {
	return &nsProvider{}
}

type nsProvider struct{}

func (p *nsProvider) Key() sdk.ObservationKey {
	return ObservationKeyNSRestrictions
}
