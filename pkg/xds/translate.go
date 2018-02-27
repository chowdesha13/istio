// Copyright 2018 Istio Authors
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

package xds

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	"github.com/gogo/protobuf/types"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/wrappers"

	routingv2 "istio.io/api/routing/v1alpha2"
	"istio.io/istio/pkg/log"
)

// Headers with special meaning in Envoy
const (
	HeaderMethod    = ":method"
	HeaderAuthority = ":authority"
	HeaderScheme    = ":scheme"
)

// TranslateRoute creates a route from match condition
func TranslateRoute(in *routingv2.HTTPMatchRequest) route.RouteMatch {
	out := route.RouteMatch{PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"}}
	if in == nil {
		return out
	}

	for name, stringMatch := range in.Headers {
		matcher := TranslateHeaderMatcher(name, stringMatch)
		out.Headers = append(out.Headers, &matcher)
	}

	// guarantee ordering of headers
	sort.Slice(out.Headers, func(i, j int) bool {
		if out.Headers[i].Name == out.Headers[j].Name {
			return out.Headers[i].Value < out.Headers[j].Value
		}
		return out.Headers[i].Name < out.Headers[j].Name
	})

	if in.Uri != nil {
		switch m := in.Uri.MatchType.(type) {
		case *routingv2.StringMatch_Exact:
			out.PathSpecifier = &route.RouteMatch_Path{Path: m.Exact}
		case *routingv2.StringMatch_Prefix:
			out.PathSpecifier = &route.RouteMatch_Prefix{Prefix: m.Prefix}
		case *routingv2.StringMatch_Regex:
			out.PathSpecifier = &route.RouteMatch_Regex{Regex: m.Regex}
		}
	}

	if in.Method != nil {
		matcher := TranslateHeaderMatcher(HeaderMethod, in.Method)
		out.Headers = append(out.Headers, &matcher)
	}

	if in.Authority != nil {
		matcher := TranslateHeaderMatcher(HeaderAuthority, in.Authority)
		out.Headers = append(out.Headers, &matcher)
	}

	if in.Scheme != nil {
		matcher := TranslateHeaderMatcher(HeaderScheme, in.Scheme)
		out.Headers = append(out.Headers, &matcher)
	}

	// TODO: match.DestinationPorts

	return out
}

// TranslateHeaderMatcher translates to HeaderMatcher
func TranslateHeaderMatcher(name string, in *routingv2.StringMatch) route.HeaderMatcher {
	out := route.HeaderMatcher{
		Name: name,
	}

	switch m := in.MatchType.(type) {
	case *routingv2.StringMatch_Exact:
		out.Value = m.Exact
	case *routingv2.StringMatch_Prefix:
		// Envoy regex grammar is ECMA-262 (http://en.cppreference.com/w/cpp/regex/ecmascript)
		// Golang has a slightly different regex grammar
		out.Value = fmt.Sprintf("^%s.*", regexp.QuoteMeta(m.Prefix))
		out.Regex = &types.BoolValue{Value: true}
	case *routingv2.StringMatch_Regex:
		out.Value = m.Regex
		out.Regex = &types.BoolValue{Value: true}
	}

	return out
}

// TranslateRetryPolicy translates retry policy
func TranslateRetryPolicy(in *routingv2.HTTPRetry) *route.RouteAction_RetryPolicy {
	if in != nil && in.Attempts > 0 {
		out := &route.RouteAction_RetryPolicy{
			NumRetries: &types.UInt32Value{Value: uint32(in.GetAttempts())},
			RetryOn:    "5xx,connect-failure,refused-stream",
		}
		if timeout := convertTime(in.PerTryTimeout); timeout > 0 {
			out.PerTryTimeout = &timeout
		}
	}
	return nil
}

// TranslateCORSPolicy translates CORS policy
func TranslateCORSPolicy(in *routingv2.CorsPolicy) *route.CorsPolicy {
	if in == nil {
		return nil
	}

	out := route.CorsPolicy{
		AllowOrigin: in.AllowOrigin,
		Enabled:     &types.BoolValue{Value: true},
	}
	if in.AllowCredentials != nil {
		out.AllowCredentials = convertBool(in.AllowCredentials)
	}
	if len(in.AllowHeaders) > 0 {
		out.AllowHeaders = strings.Join(in.AllowHeaders, ",")
	}
	if len(in.AllowMethods) > 0 {
		out.AllowMethods = strings.Join(in.AllowMethods, ",")
	}
	if len(in.ExposeHeaders) > 0 {
		out.ExposeHeaders = strings.Join(in.ExposeHeaders, ",")
	}
	if in.MaxAge != nil {
		out.MaxAge = in.MaxAge.String()
	}
	return &out
}

func convertBool(in *wrappers.BoolValue) *types.BoolValue {
	if in == nil {
		return nil
	}
	return &types.BoolValue{Value: in.Value}
}

func convertTime(in *duration.Duration) time.Duration {
	if in == nil {
		return 0
	}
	out, err := ptypes.Duration(in)
	if err != nil {
		log.Warnf("error converting duration %#v, using 0: %v", in, err)
	}
	return out
}
