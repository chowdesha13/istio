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

package security_test

import (
	"reflect"
	"testing"

	"istio.io/istio/pkg/config/security"
)

func TestParseJwksURI(t *testing.T) {
	cases := []struct {
		in            string
		expected      security.JwksInfo
		expectedError bool
	}{
		{
			in:            "foo.bar.com",
			expectedError: true,
		},
		{
			in:            "tcp://foo.bar.com:abc",
			expectedError: true,
		},
		{
			in:            "http://foo.bar.com:abc",
			expectedError: true,
		},
		{
			in: "http://foo.bar.com",
			expected: security.JwksInfo{
				Hostname: "foo.bar.com",
				Scheme:   "http",
				Port:     80,
				UseSSL:   false,
			},
		},
		{
			in: "https://foo.bar.com",
			expected: security.JwksInfo{
				Hostname: "foo.bar.com",
				Scheme:   "https",
				Port:     443,
				UseSSL:   true,
			},
		},
		{
			in: "http://foo.bar.com:1234",
			expected: security.JwksInfo{
				Hostname: "foo.bar.com",
				Scheme:   "http",
				Port:     1234,
				UseSSL:   false,
			},
		},
		{
			in: "https://foo.bar.com:1234/secure/key",
			expected: security.JwksInfo{
				Hostname: "foo.bar.com",
				Scheme:   "https",
				Port:     1234,
				UseSSL:   true,
			},
		},
	}
	for _, c := range cases {
		actual, err := security.ParseJwksURI(c.in)
		if c.expectedError == (err == nil) {
			t.Fatalf("ParseJwksURI(%s): expected error (%v), got (%v)", c.in, c.expectedError, err)
		}
		if !reflect.DeepEqual(c.expected, actual) {
			t.Fatalf("expected %+v, got %+v", c.expected, actual)
		}
	}
}

func TestValidateCondition(t *testing.T) {
	cases := []struct {
		key       string
		values    []string
		wantError bool
	}{
		{
			key:    "request.headers[:authority]",
			values: []string{"productpage"},
		},
		{
			key:       "request.headers[]",
			values:    []string{"productpage"},
			wantError: true,
		},
		{
			key:    "source.ip",
			values: []string{"1.2.3.4", "5.6.7.0/24"},
		},
		{
			key:       "source.ip",
			values:    []string{"a.b.c.d"},
			wantError: true,
		},
		{
			key: "source.namespace",
		},
		{
			key: "source.user",
		},
		{
			key: "source.principal",
		},
		{
			key: "request.auth.principal",
		},
		{
			key: "request.auth.audiences",
		},
		{
			key: "request.auth.presenter",
		},
		{
			key:    "request.auth.claims[id]",
			values: []string{"123"},
		},
		{
			key:       "request.auth.claims[]",
			wantError: true,
		},
		{
			key:    "destination.ip",
			values: []string{"1.2.3.4", "5.6.7.0/24"},
		},
		{
			key:       "destination.ip",
			values:    []string{"a.b.c.d"},
			wantError: true,
		},
		{
			key:    "destination.port",
			values: []string{"80", "90"},
		},
		{
			key:       "destination.port",
			values:    []string{"80", "x"},
			wantError: true,
		},
		{
			key:       "destination.labels[app]",
			wantError: true,
		},
		{
			key:       "destination.name",
			wantError: true,
		},
		{
			key:       "destination.namespace",
			wantError: true,
		},
		{
			key:       "destination.use",
			wantError: true,
		},
		{
			key: "connection.sni",
		},
		{
			key: "experimental.envoy.filters.a.b[c]",
		},
	}
	for _, c := range cases {
		err := security.ValidateAttribute(c.key, c.values)
		if c.wantError == (err == nil) {
			t.Fatalf("ValidateAttribute(%s): want error (%v) but got (%v)", c.key, c.wantError, err)
		}
	}
}
