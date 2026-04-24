package main

import (
	"flag"
	"log"

	nsr "git.happydns.org/checker-ns-restrictions/checker"
	"git.happydns.org/checker-sdk-go/checker/server"
)

// Version is the standalone binary's version. It defaults to "custom-build"
// and is meant to be overridden by the CI at link time:
//
//	go build -ldflags "-X main.Version=1.2.3" .
var Version = "custom-build"

var listenAddr = flag.String("listen", ":8080", "HTTP listen address")

func main() {
	flag.Parse()

	// Propagate the binary version to the checker package so it shows up in
	// CheckerDefinition.Version.
	nsr.Version = Version

	srv := server.New(nsr.Provider())
	if err := srv.ListenAndServe(*listenAddr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
