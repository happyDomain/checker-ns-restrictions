package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Collect performs the NS security restriction checks for the configured
// service and returns an NSRestrictionsReport.
func (p *nsProvider) Collect(ctx context.Context, opts sdk.CheckerOptions) (any, error) {
	svc, err := serviceFromOptions(opts)
	if err != nil {
		return nil, err
	}
	if svc.Type != serviceTypeOrigin && svc.Type != serviceTypeNSOnlyOrigin {
		return nil, fmt.Errorf("service is %s, expected %s or %s", svc.Type, serviceTypeOrigin, serviceTypeNSOnlyOrigin)
	}

	domainName := ""
	if v, ok := opts["domainName"]; ok {
		if s, ok := v.(string); ok {
			domainName = s
		}
	}
	if domainName == "" {
		domainName = svc.Domain
	}
	if domainName == "" {
		return nil, fmt.Errorf("domain name not provided and not present in service")
	}

	nameServers := nsFromService(svc)
	if len(nameServers) == 0 {
		return nil, fmt.Errorf("no nameservers found in service")
	}

	report := &NSRestrictionsReport{}
	for _, ns := range nameServers {
		nsHost := strings.TrimSuffix(ns.Ns, ".")
		results := checkNameServer(ctx, domainName, nsHost)
		report.Servers = append(report.Servers, results...)
	}

	return report, nil
}

// serviceFromOptions extracts a *serviceMessage from the options. It accepts
// either a direct value (in-process plugin path) or a JSON-decoded
// map[string]any (HTTP path) — both are normalized via a JSON round-trip.
func serviceFromOptions(opts sdk.CheckerOptions) (*serviceMessage, error) {
	v, ok := opts["service"]
	if !ok {
		return nil, fmt.Errorf("service not defined")
	}

	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal service option: %w", err)
	}

	var svc serviceMessage
	if err := json.Unmarshal(raw, &svc); err != nil {
		return nil, fmt.Errorf("failed to decode service option: %w", err)
	}
	return &svc, nil
}

// checkNameServer resolves nsHost and runs checks on each address.
func checkNameServer(ctx context.Context, domain, nsHost string) []NSServerResult {
	addrs, err := net.LookupHost(nsHost)
	if err != nil {
		return []NSServerResult{{
			Name:    nsHost,
			Address: "",
			Checks: []NSCheckItem{{
				Name:   "DNS resolution",
				OK:     false,
				Detail: fmt.Sprintf("lookup failed: %s", err),
			}},
		}}
	}

	var results []NSServerResult
	for _, addr := range addrs {
		// Skip IPv6 addresses when there is no IPv6 connectivity.
		if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
			conn, err := net.DialTimeout("udp", net.JoinHostPort(addr, "53"), 3*time.Second)
			if errors.Is(err, syscall.ENETUNREACH) {
				results = append(results, NSServerResult{
					Name:    nsHost,
					Address: addr,
					Checks: []NSCheckItem{{
						Name:   "IPv6 connectivity",
						OK:     true,
						Detail: "unable to test due to the lack of IPv6 connectivity",
					}},
				})
				continue
			}
			if conn != nil {
				conn.Close()
			}
		}

		results = append(results, checkServerAddr(ctx, domain, nsHost, addr))
	}

	return results
}
