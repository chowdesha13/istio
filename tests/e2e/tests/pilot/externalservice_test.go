// Copyright 2017 Istio Authors
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

package pilot

import (
	"fmt"
	"testing"

	"istio.io/istio/pkg/log"
)

func TestServiceEntry(t *testing.T) {
	// This list is ordered so that cases that use the same egress rule are adjacent. This is
	// done to avoid applying config changes more than necessary.
	cases := []struct {
		name              string
		config            string
		url               string
		shouldBeReachable bool
	}{
		{
			name:              "REACHABLE_www.google.com_over_google_80",
			config:            "testdata/networking/v1alpha3/service-entry-google.yaml",
			url:               "http://www.google.com",
			shouldBeReachable: true,
		},
		{
			name:              "REACHABLE_www.google.com_over_google_443",
			config:            "testdata/networking/v1alpha3/service-entry-google.yaml",
			url:               "https://www.google.com",
			shouldBeReachable: true,
		},
		{
			name:              "UNREACHABLE_bing.com_over_google_443",
			config:            "testdata/networking/v1alpha3/service-entry-google.yaml",
			url:               "https://bing.com",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_bing.com_over_google_80",
			config:            "testdata/networking/v1alpha3/service-entry-google.yaml",
			url:               "http://www.bing.com",
			shouldBeReachable: false,
		},
		{
			name:              "REACHABLE_www.bing.com_over_bing_wildcard_80",
			config:            "testdata/networking/v1alpha3/service-entry-wildcard-bing.yaml",
			url:               "http://www.bing.com",
			shouldBeReachable: true,
		},
		{
			name:              "UNREACHABLE_bing.com_over_bing_wildcard_80",
			config:            "testdata/networking/v1alpha3/service-entry-wildcard-bing.yaml",
			url:               "http://bing.com",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_bing.com_over_bing_wildcard_443",
			config:            "testdata/networking/v1alpha3/service-entry-wildcard-bing.yaml",
			url:               "https://www.bing.com",
			shouldBeReachable: false,
		},
		{
			name:              "REACHABLE_wikipedia.org_over_cidr_range",
			config:            "testdata/networking/v1alpha3/service-entry-tcp-wikipedia-cidr.yaml",
			url:               "https://www.wikipedia.org",
			shouldBeReachable: true,
		},
		{
			name:              "UNREACHABLE_google.com_over_cidr_range",
			config:            "testdata/networking/v1alpha3/service-entry-tcp-wikipedia-cidr.yaml",
			url:               "https://google.com",
			shouldBeReachable: false,
		},
		{
			name:              "REACHABLE_en.wikipedia.org_over_wikipedia_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia.yaml",
			url:               "https://en.wikipedia.org/wiki/Main_Page",
			shouldBeReachable: true,
		},
		{
			name:              "REACHABLE_de.wikipedia.org_over_wikipedia_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia.yaml",
			url:               "https://de.wikipedia.org/wiki/Wikipedia:Hauptseite",
			shouldBeReachable: true,
		},
		{
			name:              "UNREACHABLE_www.wikipedia.org_over_wikipedia_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia.yaml",
			url:               "https://www.wikipedia.org",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_en.wikipedia.org_no_vs_over_wikipedia_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia-no-vs.yaml",
			url:               "https://en.wikipedia.org/wiki/Main_Page",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_de.wikipedia.org_no_vs_over_wikipedia_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia-no-vs.yaml",
			url:               "https://de.wikipedia.org/wiki/Wikipedia:Hauptseite",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_www.wikipedia.org_no_vs_over_wikipedia_wildcard_443",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia-no-vs.yaml",
			url:               "https://www.wikipedia.org",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_www.wikipedia.org_no_vs_over_wikipedia_wildcard_80",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia-no-vs.yaml",
			url:               "http://www.wikipedia.org",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_www.google.com_no_vs_over_wikipedia_wildcard_443",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia-no-vs.yaml",
			url:               "https://www.google.com",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_www.google.com_no_vs_over_wikipedia_wildcard_80",
			config:            "testdata/networking/v1alpha3/wildcard-tls-wikipedia-no-vs.yaml",
			url:               "http://www.google.org",
			shouldBeReachable: false,
		},
		{
			name:              "REACHABLE_en.wikipedia.org_https_no_vs_over_wikipedia_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-wikipedia-no-vs.yaml",
			url:               "https://en.wikipedia.org/wiki/Main_Page",
			shouldBeReachable: false,
		},
		{
			name:              "REACHABLE_de.wikipedia.org_https_no_vs_over_wikipedia_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-wikipedia-no-vs.yaml",
			url:               "https://de.wikipedia.org/wiki/Wikipedia:Hauptseite",
			shouldBeReachable: true,
		},
		{
			name:              "REACHABLE_www.wikipedia.org_https_no_vs_over_wikipedia_wildcard_443",
			config:            "testdata/networking/v1alpha3/wildcard-https-wikipedia-no-vs.yaml",
			url:               "https://www.wikipedia.org",
			shouldBeReachable: true,
		},
		{
			name:              "UNCREACHABLE_www.wikipedia.org_https_no_vs_over_wikipedia_wildcard_80",
			config:            "testdata/networking/v1alpha3/wildcard-https-wikipedia-no-vs.yaml",
			url:               "http://www.wikipedia.org",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_www.google.com_https_no_vs_over_wikipedia_wildcard_443",
			config:            "testdata/networking/v1alpha3/wildcard-https-wikipedia-no-vs.yaml",
			url:               "https://www.google.com",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_www.google.com__https_no_vs_over_wikipedia_wildcard_80",
			config:            "testdata/networking/v1alpha3/wildcard-https-wikipedia-no-vs.yaml",
			url:               "http://www.google.org",
			shouldBeReachable: false,
		},
		{
			name:              "REACHABLE_google_no_vs_over_multihosts_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-multihosts-no-vs.yaml",
			url:               "https://www.google.com",
			shouldBeReachable: true,
		},
		{
			name:              "REACHABLE_bing_no_vs_over_multihosts_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-multihosts-no-vs.yaml",
			url:               "https://www.bing.com",
			shouldBeReachable: true,
		},
		{
			name:              "UNREACHABLE_google_no_vs_over_multihosts_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-multihosts-no-vs.yaml",
			url:               "http://www.google.com",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_bing_no_vs_over_multihosts_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-multihosts-no-vs.yaml",
			url:               "http://www.bing.com",
			shouldBeReachable: false,
		},
		{
			name:              "UNREACHABLE_wikipedia_no_vs_over_multihosts_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-multihosts-no-vs.yaml",
			url:               "https://www.wikipedia.org",
			shouldBeReachable: false,
		},
		{
			name:              "REACHABLE_cn_bing_no_vs_over_multihosts_wildcard",
			config:            "testdata/networking/v1alpha3/wildcard-https-multihosts-no-vs.yaml",
			url:               "https://cn.bing.com",
			shouldBeReachable: true,
		},
	}

	var cfgs *deployableConfig
	applyRuleFunc := func(t *testing.T, ruleYaml string) {
		configChange := cfgs == nil || cfgs.YamlFiles[0] != ruleYaml
		if configChange {
			// Delete the previous rule if there was one. No delay on the teardown, since we're going to apply
			// a delay when we push the new config.
			if cfgs != nil {
				if err := cfgs.TeardownNoDelay(); err != nil {
					t.Fatal(err)
				}
				cfgs = nil
			}

			// Apply the new rule
			cfgs = &deployableConfig{
				Namespace:  tc.Kube.Namespace,
				YamlFiles:  []string{ruleYaml},
				kubeconfig: tc.Kube.KubeConfig,
			}
			if err := cfgs.Setup(); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Upon function exit, delete the active rule.
	defer func() {
		if cfgs != nil {
			_ = cfgs.Teardown()
		}
	}()

	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			// Apply the rule
			applyRuleFunc(t, cs.config)

			for cluster := range tc.Kube.Clusters {
				// Make the requests and verify the reachability
				for _, src := range []string{"a"} {
					runRetriableTest(t, "from_"+src, 3, func() error {
						resp := ClientRequest(cluster, src, cs.url, 1, "")
						reachable := resp.IsHTTPOk()
						if reachable && !cs.shouldBeReachable {
							return fmt.Errorf("%s is reachable from %s (should be unreachable)", cs.url, src)
						}
						if !reachable && cs.shouldBeReachable {
							log.Errorf("%s is not reachable while it should be reachable from %s", cs.url, src)
							return errAgain
						}

						return nil
					})
				}
			}
		})
	}
}
