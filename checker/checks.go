package checker

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dnsPort is the DNS service port used for every query made by this checker.
const dnsPort = "53"

// defaultQueryTimeout bounds every UDP query this checker issues.
const defaultQueryTimeout = 5 * time.Second

// exchangeUDP issues a single UDP DNS query, bound to ctx.
func exchangeUDP(ctx context.Context, msg *dns.Msg, addr string) (*dns.Msg, error) {
	cl := &dns.Client{Net: "udp", Timeout: defaultQueryTimeout}
	resp, _, err := cl.ExchangeContext(ctx, msg, net.JoinHostPort(addr, dnsPort))
	return resp, err
}

// probeAXFR attempts a zone transfer and returns raw facts about it.
func probeAXFR(ctx context.Context, domain, addr string) AXFRProbe {
	msg := new(dns.Msg)
	msg.SetAxfr(dns.Fqdn(domain))

	t := &dns.Transfer{
		DialTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second,
	}

	done := make(chan AXFRProbe, 1)
	go func() {
		ch, err := t.In(msg, net.JoinHostPort(addr, dnsPort))
		if err != nil {
			done <- AXFRProbe{Accepted: false, Reason: fmt.Sprintf("transfer refused: %s", err)}
			return
		}
		// Drain channel even after a verdict: stopping reads would
		// block miekg/dns' sender goroutine on the TCP connection.
		verdict := AXFRProbe{Accepted: false, Reason: "AXFR refused"}
		for env := range ch {
			if env.Error != nil {
				// Don't downgrade an already-accepted verdict:
				// a late transport error after the SOA arrived
				// must not erase the fact that the zone was
				// served.
				if !verdict.Accepted {
					verdict = AXFRProbe{Accepted: false, Reason: fmt.Sprintf("transfer error: %s", env.Error)}
				}
				continue
			}
			for _, rr := range env.RR {
				if rr.Header().Rrtype == dns.TypeSOA {
					verdict = AXFRProbe{Accepted: true}
				}
			}
		}
		done <- verdict
	}()

	select {
	case <-ctx.Done():
		return AXFRProbe{Cancelled: true, Reason: fmt.Sprintf("AXFR check cancelled: %s", ctx.Err())}
	case r := <-done:
		return r
	}
}

// probeIXFR issues a single IXFR query and returns the raw response facts.
func probeIXFR(ctx context.Context, domain, addr string) IXFRProbe {
	msg := new(dns.Msg)
	msg.SetIxfr(dns.Fqdn(domain), 0, "", "")

	resp, err := exchangeUDP(ctx, msg, addr)
	if err != nil {
		return IXFRProbe{Error: err.Error()}
	}
	return IXFRProbe{
		Rcode:       dns.RcodeToString[resp.Rcode],
		AnswerCount: len(resp.Answer),
	}
}

// probeSOA issues a SOA query with RD=1 and captures the RA and AA bits.
func probeSOA(ctx context.Context, domain, addr string) SOAProbe {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	msg.RecursionDesired = true

	resp, err := exchangeUDP(ctx, msg, addr)
	if err != nil {
		return SOAProbe{Error: err.Error()}
	}
	return SOAProbe{
		RecursionAvailable: resp.RecursionAvailable,
		Authoritative:      resp.Authoritative,
	}
}

// probeANY issues an ANY query and records raw facts about the answer.
func probeANY(ctx context.Context, domain, addr string) ANYProbe {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeANY)

	resp, err := exchangeUDP(ctx, msg, addr)
	if err != nil {
		return ANYProbe{Error: err.Error()}
	}
	out := ANYProbe{
		Rcode:       dns.RcodeToString[resp.Rcode],
		AnswerCount: len(resp.Answer),
	}
	if len(resp.Answer) > 0 {
		hinfoOnly := true
		for _, rr := range resp.Answer {
			if _, ok := rr.(*dns.HINFO); !ok {
				hinfoOnly = false
				break
			}
		}
		out.HINFOOnly = hinfoOnly
	}
	return out
}

// probeServerAddr runs every raw probe against a single IP address in parallel
// and returns a populated NSServerResult with no pass/fail judgment applied.
func probeServerAddr(ctx context.Context, domain, nsHost, addr string) NSServerResult {
	var (
		wg   sync.WaitGroup
		axfr AXFRProbe
		ixfr IXFRProbe
		soa  SOAProbe
		any  ANYProbe
	)
	wg.Add(4)
	go func() { defer wg.Done(); axfr = probeAXFR(ctx, domain, addr) }()
	go func() { defer wg.Done(); ixfr = probeIXFR(ctx, domain, addr) }()
	go func() { defer wg.Done(); soa = probeSOA(ctx, domain, addr) }()
	go func() { defer wg.Done(); any = probeANY(ctx, domain, addr) }()
	wg.Wait()

	return NSServerResult{
		Name:    nsHost,
		Address: addr,
		AXFR:    axfr,
		IXFR:    ixfr,
		SOA:     soa,
		ANY:     any,
	}
}
