package checker

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	sdk "git.happydns.org/checker-sdk-go/checker"
)

// fakeObs is a synthetic ObservationGetter that returns a pre-built report
// (or a fixed error) when asked for ObservationKeyNSRestrictions.
type fakeObs struct {
	report *NSRestrictionsReport
	err    error
}

func (f *fakeObs) Get(_ context.Context, key sdk.ObservationKey, dest any) error {
	if f.err != nil {
		return f.err
	}
	if key != ObservationKeyNSRestrictions {
		return errors.New("unexpected key: " + key)
	}
	raw, err := json.Marshal(f.report)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, dest)
}

func (f *fakeObs) GetRelated(_ context.Context, _ sdk.ObservationKey) ([]sdk.RelatedObservation, error) {
	return nil, nil
}

func obsWith(report *NSRestrictionsReport) *fakeObs { return &fakeObs{report: report} }
func obsErr(err error) *fakeObs                     { return &fakeObs{err: err} }

func evalOne(t *testing.T, r sdk.CheckRule, obs sdk.ObservationGetter) []sdk.CheckState {
	t.Helper()
	return r.Evaluate(context.Background(), obs, sdk.CheckerOptions{})
}

func mustOne(t *testing.T, states []sdk.CheckState) sdk.CheckState {
	t.Helper()
	if len(states) != 1 {
		t.Fatalf("expected 1 state, got %d: %+v", len(states), states)
	}
	return states[0]
}

// --- Generic preamble: load error + no probes ---------------------------

// rulesUnderTest enumerates every rule registered by Rules() with the
// expected error and skipped codes per rule. Keep in sync with Rules().
var rulesUnderTest = []struct {
	rule        sdk.CheckRule
	errCode     string
	skippedCode string
	// resolutionRule emits a single OK state when there is no failure,
	// not the "no probes" sentinel: it is the rule that owns the
	// resolution-error rows. Skip its no-probes test.
	skipNoProbes bool
}{
	{rule: &resolutionRule{}, errCode: "ns_resolution_error", skippedCode: "ns_resolution_skipped", skipNoProbes: true},
	{rule: &axfrRule{}, errCode: "ns_axfr_error", skippedCode: "ns_axfr_skipped"},
	{rule: &ixfrRule{}, errCode: "ns_ixfr_error", skippedCode: "ns_ixfr_skipped"},
	{rule: &noRecursionRule{}, errCode: "ns_recursion_error", skippedCode: "ns_recursion_skipped"},
	{rule: &anyRFC8482Rule{}, errCode: "ns_any_error", skippedCode: "ns_any_skipped"},
	{rule: &authoritativeRule{}, errCode: "ns_authoritative_error", skippedCode: "ns_authoritative_skipped"},
}

func TestRules_LoadErrorPropagated(t *testing.T) {
	for _, tt := range rulesUnderTest {
		t.Run(tt.rule.Name(), func(t *testing.T) {
			st := mustOne(t, evalOne(t, tt.rule, obsErr(errors.New("boom"))))
			if st.Status != sdk.StatusError {
				t.Errorf("status = %v, want StatusError", st.Status)
			}
			if st.Code != tt.errCode {
				t.Errorf("code = %q, want %q", st.Code, tt.errCode)
			}
		})
	}
}

func TestRules_NoProbesEmitsSkipped(t *testing.T) {
	// All resolution-failed servers: probedServers() returns empty.
	report := &NSRestrictionsReport{
		Servers: []NSServerResult{{Name: "ns1.example.com", ResolutionError: "nxdomain"}},
	}
	for _, tt := range rulesUnderTest {
		if tt.skipNoProbes {
			continue
		}
		t.Run(tt.rule.Name(), func(t *testing.T) {
			st := mustOne(t, evalOne(t, tt.rule, obsWith(report)))
			if st.Status != sdk.StatusUnknown {
				t.Errorf("status = %v, want StatusUnknown", st.Status)
			}
			if st.Code != tt.skippedCode {
				t.Errorf("code = %q, want %q", st.Code, tt.skippedCode)
			}
		})
	}
}

// --- resolutionRule ------------------------------------------------------

func TestResolutionRule(t *testing.T) {
	t.Run("all resolved -> single OK", func(t *testing.T) {
		report := &NSRestrictionsReport{
			Servers: []NSServerResult{
				{Name: "ns1.example.com", Address: "192.0.2.1"},
				{Name: "ns2.example.com", Address: "192.0.2.2"},
			},
		}
		st := mustOne(t, evalOne(t, &resolutionRule{}, obsWith(report)))
		if st.Status != sdk.StatusOK || st.Code != "ns_resolution_ok" {
			t.Errorf("got status=%v code=%q, want OK ns_resolution_ok", st.Status, st.Code)
		}
	})

	t.Run("one failure -> Crit per failed NS, no OK", func(t *testing.T) {
		report := &NSRestrictionsReport{
			Servers: []NSServerResult{
				{Name: "ns1.example.com", Address: "192.0.2.1"},
				{Name: "broken.example.com", ResolutionError: "no such host"},
			},
		}
		states := evalOne(t, &resolutionRule{}, obsWith(report))
		if len(states) != 1 {
			t.Fatalf("got %d states, want 1", len(states))
		}
		if states[0].Status != sdk.StatusCrit || states[0].Code != "ns_resolution_failed" {
			t.Errorf("got status=%v code=%q, want Crit ns_resolution_failed", states[0].Status, states[0].Code)
		}
		if states[0].Subject != "broken.example.com" {
			t.Errorf("subject = %q, want broken.example.com", states[0].Subject)
		}
	})
}

// --- axfrRule ------------------------------------------------------------

func TestAxfrRule(t *testing.T) {
	srv := func(axfr AXFRProbe) NSServerResult {
		return NSServerResult{Name: "ns1.example.com", Address: "192.0.2.1", AXFR: axfr}
	}
	tests := []struct {
		name   string
		probe  AXFRProbe
		status sdk.Status
		code   string
	}{
		{"refused -> OK with reason", AXFRProbe{Reason: "transfer refused: REFUSED"}, sdk.StatusOK, "ns_axfr_ok"},
		{"refused with empty reason -> OK with default message",
			AXFRProbe{}, sdk.StatusOK, "ns_axfr_ok"},
		{"accepted -> Crit", AXFRProbe{Accepted: true}, sdk.StatusCrit, "ns_axfr_accepted"},
		{"cancelled -> Unknown", AXFRProbe{Cancelled: true, Reason: "ctx cancelled"}, sdk.StatusUnknown, "ns_axfr_skipped"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &NSRestrictionsReport{Servers: []NSServerResult{srv(tt.probe)}}
			st := mustOne(t, evalOne(t, &axfrRule{}, obsWith(report)))
			if st.Status != tt.status || st.Code != tt.code {
				t.Errorf("got status=%v code=%q, want %v %q", st.Status, st.Code, tt.status, tt.code)
			}
			if st.Message == "" {
				t.Error("empty message")
			}
		})
	}
}

// --- ixfrRule ------------------------------------------------------------

func TestIxfrRule(t *testing.T) {
	srv := func(p IXFRProbe) NSServerResult {
		return NSServerResult{Name: "ns1.example.com", Address: "192.0.2.1", IXFR: p}
	}
	tests := []struct {
		name   string
		probe  IXFRProbe
		status sdk.Status
		code   string
	}{
		{"transport error -> OK", IXFRProbe{Error: "i/o timeout"}, sdk.StatusOK, "ns_ixfr_ok"},
		{"refused rcode -> OK", IXFRProbe{Rcode: "REFUSED"}, sdk.StatusOK, "ns_ixfr_ok"},
		{"NOERROR with answers -> Warn", IXFRProbe{Rcode: "NOERROR", AnswerCount: 3}, sdk.StatusWarn, "ns_ixfr_accepted"},
		{"NOERROR empty -> OK", IXFRProbe{Rcode: "NOERROR"}, sdk.StatusOK, "ns_ixfr_ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &NSRestrictionsReport{Servers: []NSServerResult{srv(tt.probe)}}
			st := mustOne(t, evalOne(t, &ixfrRule{}, obsWith(report)))
			if st.Status != tt.status || st.Code != tt.code {
				t.Errorf("got status=%v code=%q, want %v %q", st.Status, st.Code, tt.status, tt.code)
			}
		})
	}
}

// --- noRecursionRule -----------------------------------------------------

func TestNoRecursionRule(t *testing.T) {
	srv := func(p SOAProbe) NSServerResult {
		return NSServerResult{Name: "ns1.example.com", Address: "192.0.2.1", SOA: p}
	}
	tests := []struct {
		name   string
		probe  SOAProbe
		status sdk.Status
		code   string
	}{
		{"transport error -> Unknown", SOAProbe{Error: "timeout"}, sdk.StatusUnknown, "ns_recursion_skipped"},
		{"RA set -> Warn", SOAProbe{RecursionAvailable: true}, sdk.StatusWarn, "ns_recursion_available"},
		{"RA unset -> OK", SOAProbe{}, sdk.StatusOK, "ns_recursion_ok"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &NSRestrictionsReport{Servers: []NSServerResult{srv(tt.probe)}}
			st := mustOne(t, evalOne(t, &noRecursionRule{}, obsWith(report)))
			if st.Status != tt.status || st.Code != tt.code {
				t.Errorf("got status=%v code=%q, want %v %q", st.Status, st.Code, tt.status, tt.code)
			}
		})
	}
}

// --- anyRFC8482Rule ------------------------------------------------------

func TestAnyRule(t *testing.T) {
	srv := func(p ANYProbe) NSServerResult {
		return NSServerResult{Name: "ns1.example.com", Address: "192.0.2.1", ANY: p}
	}
	tests := []struct {
		name   string
		probe  ANYProbe
		status sdk.Status
		code   string
	}{
		{"transport error -> Unknown", ANYProbe{Error: "timeout"}, sdk.StatusUnknown, "ns_any_skipped"},
		{"refused -> OK", ANYProbe{Rcode: "REFUSED"}, sdk.StatusOK, "ns_any_ok"},
		{"HINFO only -> OK", ANYProbe{Rcode: "NOERROR", AnswerCount: 1, HINFOOnly: true}, sdk.StatusOK, "ns_any_ok"},
		{"empty answer -> OK", ANYProbe{Rcode: "NOERROR"}, sdk.StatusOK, "ns_any_ok"},
		{"full answer -> Warn", ANYProbe{Rcode: "NOERROR", AnswerCount: 5}, sdk.StatusWarn, "ns_any_non_compliant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &NSRestrictionsReport{Servers: []NSServerResult{srv(tt.probe)}}
			st := mustOne(t, evalOne(t, &anyRFC8482Rule{}, obsWith(report)))
			if st.Status != tt.status || st.Code != tt.code {
				t.Errorf("got status=%v code=%q, want %v %q", st.Status, st.Code, tt.status, tt.code)
			}
		})
	}
}

// --- authoritativeRule ---------------------------------------------------

func TestAuthoritativeRule(t *testing.T) {
	srv := func(p SOAProbe) NSServerResult {
		return NSServerResult{Name: "ns1.example.com", Address: "192.0.2.1", SOA: p}
	}
	tests := []struct {
		name   string
		probe  SOAProbe
		status sdk.Status
		code   string
	}{
		{"transport error -> Info", SOAProbe{Error: "timeout"}, sdk.StatusInfo, "ns_authoritative_unknown"},
		{"AA set -> OK", SOAProbe{Authoritative: true}, sdk.StatusOK, "ns_authoritative_ok"},
		{"AA unset -> Info", SOAProbe{}, sdk.StatusInfo, "ns_authoritative_missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &NSRestrictionsReport{Servers: []NSServerResult{srv(tt.probe)}}
			st := mustOne(t, evalOne(t, &authoritativeRule{}, obsWith(report)))
			if st.Status != tt.status || st.Code != tt.code {
				t.Errorf("got status=%v code=%q, want %v %q", st.Status, st.Code, tt.status, tt.code)
			}
		})
	}
}

// --- multi-server fan-out ------------------------------------------------

// Sanity check: a rule that has 3 probed servers must return 3 states,
// each with the per-server subject. This covers the loop in every
// per-server rule and would catch a regression where the boilerplate gets
// factored incorrectly.
func TestRules_OneStatePerProbedServer(t *testing.T) {
	report := &NSRestrictionsReport{
		Servers: []NSServerResult{
			{Name: "ns1.example.com", Address: "192.0.2.1"}, // probed
			{Name: "ns2.example.com", Address: "192.0.2.2"}, // probed
			{Name: "ns3.example.com", AddressSkipped: true}, // skipped
			{Name: "ns4.example.com", ResolutionError: "x"}, // resolution failed
		},
	}
	perServer := []sdk.CheckRule{
		&axfrRule{}, &ixfrRule{}, &noRecursionRule{},
		&anyRFC8482Rule{}, &authoritativeRule{},
	}
	for _, r := range perServer {
		t.Run(r.Name(), func(t *testing.T) {
			states := evalOne(t, r, obsWith(report))
			if len(states) != 2 {
				t.Fatalf("got %d states, want 2 (one per probed server): %+v", len(states), states)
			}
			subjects := map[string]bool{}
			for _, st := range states {
				subjects[st.Subject] = true
			}
			if !subjects["ns1.example.com (192.0.2.1)"] || !subjects["ns2.example.com (192.0.2.2)"] {
				t.Errorf("subjects = %v, want both probed servers", subjects)
			}
		})
	}
}
