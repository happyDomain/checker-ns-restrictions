// Command plugin is the happyDomain plugin entrypoint for the NS security
// restrictions checker.
//
// It is built as a Go plugin (`go build -buildmode=plugin`) and loaded at
// runtime by happyDomain.
package main

import (
	nsr "git.happydns.org/checker-ns-restrictions/checker"
	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Version is the plugin's version. It defaults to "custom-build" and is
// meant to be overridden by the CI at link time:
//
//	go build -buildmode=plugin -ldflags "-X main.Version=1.2.3" -o checker-ns-restrictions.so ./plugin
var Version = "custom-build"

// NewCheckerPlugin is the symbol resolved by happyDomain when loading the
// .so file. It returns the checker definition and the observation provider
// that the host will register in its global registries.
func NewCheckerPlugin() (*sdk.CheckerDefinition, sdk.ObservationProvider, error) {
	// Propagate the plugin's version to the checker package so it shows up
	// in CheckerDefinition.Version.
	nsr.Version = Version
	return nsr.Definition(), nsr.Provider(), nil
}
