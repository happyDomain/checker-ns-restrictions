package checker

import (
	"encoding/json"
	"testing"

	sdk "git.happydns.org/checker-sdk-go/checker"
	"github.com/miekg/dns"
)

func TestBuildNSHost(t *testing.T) {
	tests := []struct {
		name       string
		ns         string
		svcDomain  string
		domainName string
		want       string
	}{
		{
			name:       "absolute NS keeps name and drops trailing dot",
			ns:         "ns1.example.net.",
			svcDomain:  "ignored",
			domainName: "example.com",
			want:       "ns1.example.net",
		},
		{
			name:       "relative NS with empty service domain appends domain",
			ns:         "ns1",
			svcDomain:  "",
			domainName: "example.com",
			want:       "ns1.example.com",
		},
		{
			name:       "relative NS with @ service domain appends only domain",
			ns:         "ns1",
			svcDomain:  "@",
			domainName: "example.com",
			want:       "ns1.example.com",
		},
		{
			name:       "relative NS with subdomain service appends both",
			ns:         "ns1",
			svcDomain:  "sub",
			domainName: "example.com",
			want:       "ns1.sub.example.com",
		},
		{
			name:       "relative NS strips trailing dot from svc domain and domain",
			ns:         "ns1",
			svcDomain:  "sub.",
			domainName: "example.com.",
			want:       "ns1.sub.example.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildNSHost(tt.ns, tt.svcDomain, tt.domainName)
			if got != tt.want {
				t.Errorf("buildNSHost(%q, %q, %q) = %q, want %q",
					tt.ns, tt.svcDomain, tt.domainName, got, tt.want)
			}
		})
	}
}

func TestServiceFromOptions(t *testing.T) {
	t.Run("missing service option", func(t *testing.T) {
		_, err := serviceFromOptions(sdk.CheckerOptions{})
		if err == nil {
			t.Fatal("expected error for missing service option, got nil")
		}
	})

	t.Run("direct value (in-process plugin)", func(t *testing.T) {
		svc := serviceMessage{
			Type:    serviceTypeOrigin,
			Domain:  "example.com",
			Service: json.RawMessage(`{"ns":[]}`),
		}
		got, err := serviceFromOptions(sdk.CheckerOptions{"service": svc})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Type != serviceTypeOrigin || got.Domain != "example.com" {
			t.Errorf("got %+v, want type=%s domain=example.com", got, serviceTypeOrigin)
		}
	})

	t.Run("decoded JSON map (HTTP path)", func(t *testing.T) {
		raw := map[string]any{
			"_svctype": serviceTypeNSOnlyOrigin,
			"_domain":  "sub",
			"Service":  map[string]any{"ns": []any{}},
		}
		got, err := serviceFromOptions(sdk.CheckerOptions{"service": raw})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Type != serviceTypeNSOnlyOrigin || got.Domain != "sub" {
			t.Errorf("got %+v, want type=%s domain=sub", got, serviceTypeNSOnlyOrigin)
		}
	})
}

func TestNSFromService(t *testing.T) {
	t.Run("origin payload returns NS records", func(t *testing.T) {
		payload, _ := json.Marshal(nsPayload{NameServers: []*dns.NS{
			{Ns: "ns1.example.com."},
			{Ns: "ns2.example.com."},
		}})
		svc := &serviceMessage{Type: serviceTypeOrigin, Service: payload}

		got := nsFromService(svc)
		if len(got) != 2 || got[0].Ns != "ns1.example.com." {
			t.Errorf("got %+v, want 2 NS records", got)
		}
	})

	t.Run("unknown service type returns nil", func(t *testing.T) {
		svc := &serviceMessage{Type: "abstract.NotAnOrigin", Service: json.RawMessage(`{}`)}
		if got := nsFromService(svc); got != nil {
			t.Errorf("got %+v, want nil", got)
		}
	})

	t.Run("malformed payload returns nil", func(t *testing.T) {
		svc := &serviceMessage{Type: serviceTypeOrigin, Service: json.RawMessage(`not json`)}
		if got := nsFromService(svc); got != nil {
			t.Errorf("got %+v, want nil", got)
		}
	})
}
