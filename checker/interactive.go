//go:build standalone

package checker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	sdk "git.happydns.org/checker-sdk-go/checker"
	"github.com/miekg/dns"
)

// resolveNSTimeout bounds the total time spent attempting NS resolution
// across all configured fallback resolvers.
const resolveNSTimeout = 15 * time.Second

// RenderForm implements server.Interactive. It lists the minimal human
// inputs needed to bootstrap a check when this checker runs standalone
// (outside of a happyDomain host).
func (p *nsProvider) RenderForm() []sdk.CheckerOptionField {
	return []sdk.CheckerOptionField{
		{
			Id:          "domain",
			Type:        "string",
			Label:       "Domain name",
			Placeholder: "example.com",
			Required:    true,
			Description: "Zone to probe. Its NS records will be resolved and each nameserver tested.",
		},
	}
}

// ParseForm implements server.Interactive. It resolves the NS records
// for the requested domain via DNS and assembles the CheckerOptions that
// Collect expects, replacing the AutoFill work that happyDomain would
// otherwise perform.
func (p *nsProvider) ParseForm(r *http.Request) (sdk.CheckerOptions, error) {
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" {
		return nil, errors.New("domain is required")
	}
	fqdn := dns.Fqdn(domain)

	nsRecords, err := resolveNS(fqdn)
	if err != nil {
		return nil, fmt.Errorf("could not resolve NS records for %s: %w", domain, err)
	}
	if len(nsRecords) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", domain)
	}

	payload, err := json.Marshal(nsPayload{NameServers: nsRecords})
	if err != nil {
		return nil, fmt.Errorf("failed to encode origin payload: %w", err)
	}

	svc := serviceMessage{
		Type:    serviceTypeOrigin,
		Domain:  "",
		Service: payload,
	}

	return sdk.CheckerOptions{
		"service":    svc,
		"domainName": strings.TrimSuffix(fqdn, "."),
	}, nil
}

// resolveNS queries the system resolver for the NS records of fqdn and
// returns them as miekg *dns.NS records so they match the shape produced
// by happyDomain's Origin service payload.
func resolveNS(fqdn string) ([]*dns.NS, error) {
	ctx, cancel := context.WithTimeout(context.Background(), resolveNSTimeout)
	defer cancel()

	c := &dns.Client{Timeout: defaultQueryTimeout}
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeNS)
	m.RecursionDesired = true

	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || config == nil || len(config.Servers) == 0 {
		config = &dns.ClientConfig{Servers: []string{"1.1.1.1", "8.8.8.8"}, Port: dnsPort}
	}

	var lastErr error
	for _, server := range config.Servers {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				lastErr = err
			}
			break
		}
		in, _, err := c.ExchangeContext(ctx, m, net.JoinHostPort(server, config.Port))
		if err != nil {
			lastErr = err
			continue
		}
		if in.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS response code %s", dns.RcodeToString[in.Rcode])
			continue
		}
		var records []*dns.NS
		for _, rr := range in.Answer {
			if ns, ok := rr.(*dns.NS); ok {
				records = append(records, ns)
			}
		}
		return records, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no resolver available")
	}
	return nil, lastErr
}
