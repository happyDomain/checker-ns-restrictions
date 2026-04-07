package checker

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// checkAXFR returns (ok bool, detail string).
// ok=false means the server accepted the zone transfer (CRITICAL).
func checkAXFR(ctx context.Context, domain, addr string) (bool, string) {
	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	t := &dns.Transfer{}
	t.DialTimeout = 5 * time.Second
	t.ReadTimeout = 10 * time.Second

	ch, err := t.In(msg, net.JoinHostPort(addr, "53"))
	if err != nil {
		return true, fmt.Sprintf("transfer refused: %s", err)
	}

	for env := range ch {
		if env.Error != nil {
			return true, fmt.Sprintf("transfer error: %s", env.Error)
		}
		for _, rr := range env.RR {
			if rr.Header().Rrtype == dns.TypeSOA {
				return false, "AXFR zone transfer accepted"
			}
		}
	}

	return true, "AXFR refused"
}

// checkIXFR returns (ok bool, detail string).
// ok=false means the server answered with records (WARN).
func checkIXFR(ctx context.Context, domain, addr string) (bool, string) {
	msg := new(dns.Msg)
	msg.SetIxfr(dns.Fqdn(domain), 0, "", "")

	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := cl.ExchangeContext(ctx, msg, net.JoinHostPort(addr, "53"))
	if err != nil {
		return true, fmt.Sprintf("query failed: %s", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return true, fmt.Sprintf("IXFR refused (rcode=%s)", dns.RcodeToString[resp.Rcode])
	}
	if len(resp.Answer) > 0 {
		return false, fmt.Sprintf("IXFR accepted with %d answer(s)", len(resp.Answer))
	}

	return true, "IXFR refused or empty"
}

// checkNoRecursion returns (ok bool, detail string).
// ok=false means the server offers recursion (WARN).
func checkNoRecursion(ctx context.Context, domain, addr string) (bool, string) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	msg.RecursionDesired = true

	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := cl.ExchangeContext(ctx, msg, net.JoinHostPort(addr, "53"))
	if err != nil {
		return true, fmt.Sprintf("query failed: %s", err)
	}

	if resp.RecursionAvailable {
		return false, "recursion available (RA bit set)"
	}
	return true, "recursion not available"
}

// checkANYHandled returns (ok bool, detail string).
// ok=false means the server returned a full record set for ANY (WARN).
// Per RFC 8482, servers should return HINFO or a minimal response.
func checkANYHandled(ctx context.Context, domain, addr string) (bool, string) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeANY)

	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := cl.ExchangeContext(ctx, msg, net.JoinHostPort(addr, "53"))
	if err != nil {
		return true, fmt.Sprintf("query failed: %s", err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return true, fmt.Sprintf("ANY refused (rcode=%s)", dns.RcodeToString[resp.Rcode])
	}

	if len(resp.Answer) == 1 {
		if _, ok := resp.Answer[0].(*dns.HINFO); ok {
			return true, "RFC 8482 compliant HINFO response"
		}
	}

	if len(resp.Answer) == 0 {
		return true, "ANY returned empty answer"
	}

	return false, fmt.Sprintf("ANY returned %d records (not RFC 8482 compliant)", len(resp.Answer))
}

// checkIsAuthoritative returns (ok bool, detail string).
// ok=false means the server is not authoritative for the zone (INFO).
func checkIsAuthoritative(ctx context.Context, domain, addr string) (bool, string) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)

	cl := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	resp, _, err := cl.ExchangeContext(ctx, msg, net.JoinHostPort(addr, "53"))
	if err != nil {
		return false, fmt.Sprintf("query failed: %s", err)
	}

	if resp.Authoritative {
		return true, "server is authoritative (AA bit set)"
	}
	return false, "server is not authoritative (AA bit not set)"
}

// Stable check names. They are part of the JSON wire format of
// NSRestrictionsReport and used by individual rules to look up their
// corresponding entry, so they MUST NOT change without coordinating with
// the rule definitions.
const (
	checkNameAXFR            = "AXFR refused"
	checkNameIXFR            = "IXFR refused"
	checkNameNoRecursion     = "No recursion"
	checkNameANYHandled      = "ANY handled (RFC 8482)"
	checkNameIsAuthoritative = "Is authoritative"
)

// checkServerAddr runs all NS security checks against a single IP address.
func checkServerAddr(ctx context.Context, domain, nsHost, addr string) NSServerResult {
	result := NSServerResult{Name: nsHost, Address: addr}

	type checkDef struct {
		name string
		fn   func(context.Context, string, string) (bool, string)
	}
	checks := []checkDef{
		{checkNameAXFR, checkAXFR},
		{checkNameIXFR, checkIXFR},
		{checkNameNoRecursion, checkNoRecursion},
		{checkNameANYHandled, checkANYHandled},
		{checkNameIsAuthoritative, checkIsAuthoritative},
	}

	for _, ch := range checks {
		ok, detail := ch.fn(ctx, domain, addr)
		result.Checks = append(result.Checks, NSCheckItem{Name: ch.name, OK: ok, Detail: detail})
	}

	return result
}
