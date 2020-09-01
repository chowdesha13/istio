// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dns

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"

	nds "istio.io/istio/pilot/pkg/proto"
)

var (
	agentDNSAddr = "127.0.0.1:15053"

	initErr error
)

func init() {
	initErr = initDNS()
}

func initDNS() error {
	// TODO: load certificates for TLS
	agentDNS, err := NewLocalDNSServer("ns1", "ns1.svc.cluster.local")
	if err != nil {
		return err
	}
	agentDNS.StartDNS()
	agentDNS.UpdateLookupTable(&nds.NameTable{
		Table: map[string]*nds.NameTable_NameInfo{
			"www.google.com": {
				Ips:      []string{"1.1.1.1"},
				Registry: "External",
			},
			"productpage.ns1.svc.cluster.local": {
				Ips:       []string{"9.9.9.9"},
				Registry:  "Kubernetes",
				Namespace: "ns1",
				Shortname: "productpage",
			},
			"reviews.ns2.svc.cluster.local": {
				Ips:       []string{"10.10.10.10"},
				Registry:  "Kubernetes",
				Namespace: "ns2",
				Shortname: "reviews",
			},
			"details.ns2.svc.cluster.remote": {
				Ips:       []string{"11.11.11.11", "12.12.12.12"},
				Registry:  "Kubernetes",
				Namespace: "ns2",
				Shortname: "details",
			},
			"ipv6.localhost": {
				Ips:      []string{"2001:db8:0:0:0:ff00:42:8329"},
				Registry: "External",
			},
			"dual.localhost": {
				Ips:      []string{"2.2.2.2", "2001:db8:0:0:0:ff00:42:8329"},
				Registry: "External",
			},
			"ipv4.localhost": {
				Ips:      []string{"2.2.2.2"},
				Registry: "External",
			},
		},
	})
	return nil
}

func TestDNS(t *testing.T) {
	if initErr != nil {
		t.Fatal(initErr)
	}

	testCases := []struct {
		name                     string
		host                     string
		queryAAAA                bool
		expected                 []dns.RR
		expectResolutionFailure  bool
		expectExternalResolution bool
	}{
		{
			name:     "success: non k8s host in local cache",
			host:     "www.google.com.",
			expected: a("www.google.com.", []net.IP{net.ParseIP("1.1.1.1").To4()}),
		},
		{
			name:                     "success: non k8s host not in local cache",
			host:                     "www.bing.com.",
			expectExternalResolution: true,
		},
		{
			name:     "success: k8s host - fqdn",
			host:     "productpage.ns1.svc.cluster.local.",
			expected: a("productpage.ns1.svc.cluster.local.", []net.IP{net.ParseIP("9.9.9.9").To4()}),
		},
		{
			name:     "success: k8s host - name.namespace",
			host:     "productpage.ns1.",
			expected: a("productpage.ns1.", []net.IP{net.ParseIP("9.9.9.9").To4()}),
		},
		{
			name:     "success: k8s host - shortname",
			host:     "productpage.",
			expected: a("productpage.", []net.IP{net.ParseIP("9.9.9.9").To4()}),
		},
		{
			name:     "success: k8s host - non local namespace - name.namespace",
			host:     "reviews.ns2.",
			expected: a("reviews.ns2.", []net.IP{net.ParseIP("10.10.10.10").To4()}),
		},
		{
			name:     "success: k8s host - non local namespace - fqdn",
			host:     "reviews.ns2.svc.cluster.local.",
			expected: a("reviews.ns2.svc.cluster.local.", []net.IP{net.ParseIP("10.10.10.10").To4()}),
		},
		{
			name:     "success: k8s host - non local namespace - name.namespace.svc",
			host:     "reviews.ns2.svc.",
			expected: a("reviews.ns2.svc.", []net.IP{net.ParseIP("10.10.10.10").To4()}),
		},
		{
			name:                    "failure: k8s host - non local namespace - shortname",
			host:                    "reviews.",
			expectResolutionFailure: true,
		},
		{
			name: "success: remote cluster k8s svc - same ns and different domain - fqdn",
			host: "details.ns2.svc.cluster.remote.",
			expected: a("details.ns2.svc.cluster.remote.",
				[]net.IP{net.ParseIP("11.11.11.11").To4(), net.ParseIP("12.12.12.12").To4()}),
		},
		{
			name:                    "failure: remote cluster k8s svc - same ns and different domain - name.namespace",
			host:                    "details.ns2.",
			expectResolutionFailure: true, // on home machines, the ISP may resolve to some generic webpage. So this test may fail on laptops
		},
		{
			name:     "success: TypeA query returns A records only",
			host:     "dual.localhost.",
			expected: a("dual.localhost.", []net.IP{net.ParseIP("2.2.2.2").To4()}),
		},
		{
			name:      "success: TypeAAAA query returns AAAA records only",
			host:      "dual.localhost.",
			queryAAAA: true,
			expected:  aaaa("dual.localhost.", []net.IP{net.ParseIP("2001:db8:0:0:0:ff00:42:8329")}),
		},
		{
			name:                    "failure: Error response if only AAAA records exist for typeA",
			host:                    "ipv6.localhost.",
			expectResolutionFailure: true,
		},
		{
			name:                    "failure: Error response if only A records exist for typeAAAA",
			host:                    "ipv4.localhost.",
			queryAAAA:               true,
			expectResolutionFailure: true,
		},
	}

	c := dns.Client{
		Timeout: 3 * time.Second,
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			m := new(dns.Msg)
			q := dns.TypeA
			if tt.queryAAAA {
				q = dns.TypeAAAA
			}
			m.SetQuestion(tt.host, q)
			res, _, err := c.Exchange(m, agentDNSAddr)

			if err != nil {
				t.Errorf("Failed to resolve query for %s: %v", tt.host, err)
			} else {
				if tt.expectExternalResolution {
					// just make sure that the response has a valid DNS response from upstream resolvers
					if res.Rcode != dns.RcodeSuccess {
						t.Errorf("upstream dns resolution for %s failed", tt.host)
					}
				} else {
					if tt.expectResolutionFailure && res.Rcode != dns.RcodeNameError {
						t.Errorf("expected resolution failure but it succeeded for %s", tt.host)
					}
					if !equalsDNSrecords(res.Answer, tt.expected) {
						t.Errorf("dns responses for %s do not match. \n got %v\nwant %v", tt.host, res.Answer, tt.expected)
					}
				}
			}
		})
	}
}

// reflect.DeepEqual doesn't seem to work well for dns.RR
// as the Rdlength field is not updated in the a(), or aaaa() calls.
// so zero them out before doing reflect.Deepequal
func equalsDNSrecords(got []dns.RR, want []dns.RR) bool {
	for i := range got {
		got[i].Header().Rdlength = 0
	}
	return reflect.DeepEqual(got, want)
}

// Benchmark - the actual address will be cached by the local resolver.
// Baseline:
//      119us via agent if cached
//      32ms via machine resolver
// for a lookup, no match and then resolve,
//  it takes 2.3ms while direct resolution takes 2.03ms
// So the cache lookup & forward adds a 300us overhead (needs more data)
func BenchmarkDNS(t *testing.B) {
	if initErr != nil {
		t.Fatal(initErr)
	}

	t.Run("plain", func(b *testing.B) {
		bench(b, agentDNSAddr)
	})

	t.Run("public", func(b *testing.B) {
		dnsConfig, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			b.Fatal(err)
		}

		bench(b, dnsConfig.Servers[0]+":53")
	})
}

func bench(t *testing.B, dest string) {
	errs := 0
	nrs := 0
	for i := 0; i < t.N; i++ {
		c := dns.Client{
			Timeout: 1 * time.Second,
		}
		m := new(dns.Msg)
		m.SetQuestion("www.bing.com.", dns.TypeA)
		res, _, err := c.Exchange(m, dest)

		if err != nil {
			errs++
		} else if len(res.Answer) == 0 {
			nrs++
		}
	}

	if errs+nrs > 0 {
		t.Log("Sent", t.N, "err", errs, "no response", nrs)
	}

}
