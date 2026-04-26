package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// Collect gathers raw NS probe data for the configured service and returns an
// NSRestrictionsReport. It does not make any pass/fail judgment: rules derive
// status from the raw probe fields.
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

	ipv6Reachable := probeIPv6(ctx)

	all := make([][]NSServerResult, len(nameServers))
	var wg sync.WaitGroup
	wg.Add(len(nameServers))
	for i, ns := range nameServers {
		nsHost := buildNSHost(ns.Ns, svc.Domain, domainName)
		go func() {
			defer wg.Done()
			all[i] = probeNameServer(ctx, domainName, nsHost, ipv6Reachable)
		}()
	}
	wg.Wait()

	report := &NSRestrictionsReport{
		Domain:        domainName,
		IPv6Reachable: ipv6Reachable,
	}
	for _, r := range all {
		report.Servers = append(report.Servers, r...)
	}

	return report, nil
}

// buildNSHost resolves a possibly-relative NS record name against the service
// domain and the full domain name, returning an absolute host without a
// trailing dot.
func buildNSHost(ns, svcDomain, domainName string) string {
	if absolute, ok := strings.CutSuffix(ns, "."); ok {
		return absolute
	}
	host := ns
	if svcDomain != "" && svcDomain != "@" {
		host += "." + strings.TrimSuffix(svcDomain, ".")
	}
	host += "." + strings.TrimSuffix(domainName, ".")
	return host
}

// serviceFromOptions extracts a *serviceMessage from the options. It accepts
// either a direct value (in-process plugin path) or a JSON-decoded
// map[string]any (HTTP path), both are normalized via a JSON round-trip.
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

// probeIPv6 returns true if the host appears to have IPv6 connectivity. It
// dials a public DNS server over UDP once and treats ENETUNREACH as a signal
// that IPv6 is unusable on this machine.
func probeIPv6(ctx context.Context) bool {
	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "udp", net.JoinHostPort("2001:4860:4860::8888", dnsPort))
	if errors.Is(err, syscall.ENETUNREACH) {
		return false
	}
	if conn != nil {
		conn.Close()
	}
	return true
}

// probeNameServer resolves nsHost and runs raw probes on each address in
// parallel. When resolution fails, it emits one NSServerResult carrying
// ResolutionError so the dedicated rule can surface the fact.
func probeNameServer(ctx context.Context, domain, nsHost string, ipv6Reachable bool) []NSServerResult {
	addrs, err := net.LookupHost(nsHost)
	if err != nil {
		return []NSServerResult{{
			Name:            nsHost,
			ResolutionError: err.Error(),
		}}
	}

	results := make([]NSServerResult, len(addrs))
	var wg sync.WaitGroup
	wg.Add(len(addrs))
	for i, addr := range addrs {
		go func() {
			defer wg.Done()
			if !ipv6Reachable {
				if ip := net.ParseIP(addr); ip != nil && ip.To4() == nil {
					results[i] = NSServerResult{
						Name:           nsHost,
						Address:        addr,
						AddressSkipped: true,
						SkipReason:     "host lacks IPv6 connectivity",
					}
					return
				}
			}
			results[i] = probeServerAddr(ctx, domain, nsHost, addr)
		}()
	}
	wg.Wait()

	return results
}
