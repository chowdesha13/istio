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

package v1alpha3

import (
	"reflect"
	"strings"
	"testing"

	"istio.io/istio/pilot/pkg/features"
	xdsfilters "istio.io/istio/pilot/pkg/proxy/envoy/filters"

	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	wellknown "github.com/envoyproxy/go-control-plane/pkg/wellknown"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/config/protocol"
)

type LdsEnv struct {
	configgen *ConfigGeneratorImpl
}

func getDefaultLdsEnv() *LdsEnv {
	listenerEnv := LdsEnv{
		configgen: NewConfigGenerator([]plugin.Plugin{&fakePlugin{}}),
	}
	return &listenerEnv
}

func getDefaultProxy() model.Proxy {
	proxy := model.Proxy{
		Type:        model.SidecarProxy,
		IPAddresses: []string{"1.1.1.1"},
		ID:          "v0.default",
		DNSDomain:   "default.example.org",
		Metadata: &model.NodeMetadata{
			IstioVersion: "1.4",
			Namespace:    "not-default",
		},
		IstioVersion:    model.ParseIstioVersion("1.4"),
		ConfigNamespace: "not-default",
	}

	proxy.DiscoverIPVersions()
	return proxy
}

func setNilSidecarOnProxy(proxy *model.Proxy, pushContext *model.PushContext) {
	proxy.SidecarScope = model.DefaultSidecarScopeForNamespace(pushContext, "not-default")
}

func TestVirtualListenerBuilder(t *testing.T) {
	// prepare
	t.Helper()
	ldsEnv := getDefaultLdsEnv()
	service := buildService("test.com", wildcardIP, protocol.HTTP, tnow)
	services := []*model.Service{service}

	env := buildListenerEnv(services)
	if err := env.PushContext.InitContext(&env, nil, nil); err != nil {
		t.Fatalf("init push context error: %s", err.Error())
	}
	instances := make([]*model.ServiceInstance, len(services))
	for i, s := range services {
		instances[i] = &model.ServiceInstance{
			Service: s,
			Endpoint: &model.IstioEndpoint{
				EndpointPort: 8080,
			},
			ServicePort: s.Ports[0],
		}
	}
	proxy := getDefaultProxy()
	proxy.ServiceInstances = instances
	setNilSidecarOnProxy(&proxy, env.PushContext)

	builder := NewListenerBuilder(&proxy, env.PushContext)
	listeners := builder.
		buildVirtualOutboundListener(ldsEnv.configgen).
		getListeners()

	// virtual outbound listener
	if len(listeners) != 1 {
		t.Fatalf("expected %d listeners, found %d", 1, len(listeners))
	}

	if !strings.HasPrefix(listeners[0].Name, VirtualOutboundListenerName) {
		t.Fatalf("expect virtual listener, found %s", listeners[0].Name)
	} else {
		t.Logf("found virtual listener: %s", listeners[0].Name)
	}

}

func setInboundCaptureAllOnThisNode(proxy *model.Proxy, mode model.TrafficInterceptionMode) {
	proxy.Metadata.InterceptionMode = mode
}

var testServices = []*model.Service{buildService("test.com", wildcardIP, protocol.HTTP, tnow)}

func prepareListeners(t *testing.T, services []*model.Service, mode model.TrafficInterceptionMode) []*listener.Listener {
	// prepare
	ldsEnv := getDefaultLdsEnv()

	env := buildListenerEnv(services)
	if err := env.PushContext.InitContext(&env, nil, nil); err != nil {
		t.Fatalf("init push context error: %s", err.Error())
	}
	instances := make([]*model.ServiceInstance, len(services))
	for i, s := range services {
		instances[i] = &model.ServiceInstance{
			Service: s,
			Endpoint: &model.IstioEndpoint{
				EndpointPort: 8080,
			},
			ServicePort: s.Ports[0],
		}
	}

	proxy := getDefaultProxy()
	proxy.ServiceInstances = instances
	setInboundCaptureAllOnThisNode(&proxy, mode)
	setNilSidecarOnProxy(&proxy, env.PushContext)

	builder := NewListenerBuilder(&proxy, env.PushContext)
	return builder.buildSidecarInboundListeners(ldsEnv.configgen).
		buildHTTPProxyListener(ldsEnv.configgen).
		buildVirtualOutboundListener(ldsEnv.configgen).
		buildVirtualInboundListener(ldsEnv.configgen).
		getListeners()
}

func TestVirtualInboundListenerBuilder(t *testing.T) {
	defaultValue := features.EnableProtocolSniffingForInbound
	features.EnableProtocolSniffingForInbound = true
	defer func() { features.EnableProtocolSniffingForInbound = defaultValue }()

	// prepare
	t.Helper()
	listeners := prepareListeners(t, testServices, model.InterceptionRedirect)
	// virtual inbound and outbound listener
	if len(listeners) != 2 {
		t.Fatalf("expected %d listeners, found %d", 2, len(listeners))
	}

	if !strings.HasPrefix(listeners[0].Name, VirtualOutboundListenerName) {
		t.Fatalf("expect virtual listener, found %s", listeners[0].Name)
	} else {
		t.Logf("found virtual listener: %s", listeners[0].Name)
	}

	if !strings.HasPrefix(listeners[1].Name, VirtualInboundListenerName) {
		t.Fatalf("expect virtual listener, found %s", listeners[1].Name)
	} else {
		t.Logf("found virtual inbound listener: %s", listeners[1].Name)
	}

	l := listeners[1]

	byListenerName := map[string]int{}

	for _, fc := range l.FilterChains {
		byListenerName[fc.Name]++
	}

	for k, v := range byListenerName {
		if k == VirtualInboundListenerName && v != 2 {
			t.Fatalf("expect virtual listener has 2 passthrough filter chains, found %d", v)
		}
		if k == virtualInboundCatchAllHTTPFilterChainName && v != 2 {
			t.Fatalf("expect virtual listener has 2 passthrough filter chains, found %d", v)
		}
		if k == listeners[0].Name && v != len(listeners[0].FilterChains) {
			t.Fatalf("expect virtual listener has %d filter chains from listener %s, found %d", len(listeners[0].FilterChains), l.Name, v)
		}
	}
}

func TestVirtualInboundHasPassthroughClusters(t *testing.T) {
	defaultValue := features.EnableProtocolSniffingForInbound
	features.EnableProtocolSniffingForInbound = true
	defer func() { features.EnableProtocolSniffingForInbound = defaultValue }()
	// prepare
	t.Helper()
	listeners := prepareListeners(t, testServices, model.InterceptionRedirect)
	// virtual inbound and outbound listener
	if len(listeners) != 2 {
		t.Fatalf("expect %d listeners, found %d", 2, len(listeners))
	}

	l := listeners[1]
	sawFakePluginFilter := false
	sawIpv4PassthroughCluster := 0
	sawIpv6PassthroughCluster := false
	sawIpv4PsssthroughFilterChainMatchAlpnFromFakePlugin := false
	sawIpv4PsssthroughFilterChainMatchTLSFromFakePlugin := false
	for _, fc := range l.FilterChains {
		if fc.TransportSocket != nil && fc.FilterChainMatch.TransportProtocol != "tls" {
			t.Fatalf("expect passthrough filter chain sets transport protocol to tls if transport socket is set")
		}

		if len(fc.Filters) == 2 && fc.Filters[1].Name == wellknown.TCPProxy &&
			fc.Name == VirtualInboundListenerName {
			if fc.Filters[0].Name == fakePluginTCPFilter {
				sawFakePluginFilter = true
			}
			if ipLen := len(fc.FilterChainMatch.PrefixRanges); ipLen != 1 {
				t.Fatalf("expect passthrough filter chain has 1 ip address, found %d", ipLen)
			}
			for _, alpn := range fc.FilterChainMatch.ApplicationProtocols {
				if alpn == fakePluginFilterChainMatchAlpn {
					sawIpv4PsssthroughFilterChainMatchAlpnFromFakePlugin = true
				}
			}
			if fc.TransportSocket != nil {
				sawIpv4PsssthroughFilterChainMatchTLSFromFakePlugin = true
			}
			if fc.FilterChainMatch.PrefixRanges[0].AddressPrefix == util.ConvertAddressToCidr("0.0.0.0/0").AddressPrefix &&
				fc.FilterChainMatch.PrefixRanges[0].PrefixLen.Value == 0 {
				if sawIpv4PassthroughCluster == 2 {
					t.Fatalf("duplicated ipv4 passthrough cluster filter chain in listener %v", l)
				}
				sawIpv4PassthroughCluster++
			} else if fc.FilterChainMatch.PrefixRanges[0].AddressPrefix == util.ConvertAddressToCidr("::0/0").AddressPrefix &&
				fc.FilterChainMatch.PrefixRanges[0].PrefixLen.Value == 0 {
				if sawIpv6PassthroughCluster {
					t.Fatalf("duplicated ipv6 passthrough cluster filter chain in listener %v", l)
				}
				sawIpv6PassthroughCluster = true
			}
		}

		if len(fc.Filters) == 1 && fc.Filters[0].Name == wellknown.HTTPConnectionManager &&
			fc.Name == virtualInboundCatchAllHTTPFilterChainName {
			if fc.TransportSocket != nil && !reflect.DeepEqual(fc.FilterChainMatch.ApplicationProtocols, append(plaintextHTTPALPNs, mtlsHTTPALPNs...)) {
				t.Fatalf("expect %v application protocols, found %v", append(plaintextHTTPALPNs, mtlsHTTPALPNs...), fc.FilterChainMatch.ApplicationProtocols)
			}

			if fc.TransportSocket == nil && !reflect.DeepEqual(fc.FilterChainMatch.ApplicationProtocols, plaintextHTTPALPNs) {
				t.Fatalf("expect %v application protocols, found %v", plaintextHTTPALPNs, fc.FilterChainMatch.ApplicationProtocols)
			}

			if !strings.Contains(fc.Filters[0].GetTypedConfig().String(), fakePluginHTTPFilter) {
				t.Errorf("failed to find the fake plugin HTTP filter: %v", fc.Filters[0].GetTypedConfig().String())
			}
		}
	}

	if sawIpv4PassthroughCluster != 2 {
		t.Fatalf("fail to find the ipv4 passthrough filter chain in listener %v", l)
	}

	if !sawFakePluginFilter {
		t.Fatalf("fail to find the fake plugin TCP filter in listener %v", l)
	}

	if !sawIpv4PsssthroughFilterChainMatchAlpnFromFakePlugin {
		t.Fatalf("fail to find the fake plugin filter chain match with ALPN in listener %v", l)
	}

	if !sawIpv4PsssthroughFilterChainMatchTLSFromFakePlugin {
		t.Fatalf("fail to find the fake plugin filter chain match with TLS in listener %v", l)
	}

	if len(l.ListenerFilters) != 3 {
		t.Fatalf("expected %d listener filters, found %d", 3, len(l.ListenerFilters))
	}

	if l.ListenerFilters[0].Name != wellknown.OriginalDestination ||
		l.ListenerFilters[1].Name != wellknown.TlsInspector ||
		l.ListenerFilters[2].Name != wellknown.HttpInspector {
		t.Fatalf("expect listener filters [%q, %q, %q], found [%q, %q, %q]",
			wellknown.OriginalDestination, wellknown.TlsInspector, wellknown.HttpInspector,
			l.ListenerFilters[0].Name, l.ListenerFilters[1].Name, l.ListenerFilters[2].Name)
	}
}

func TestSidecarInboundListenerWithOriginalSrc(t *testing.T) {
	// prepare
	t.Helper()
	listeners := prepareListeners(t, testServices, model.InterceptionTproxy)

	if len(listeners) != 2 {
		t.Fatalf("expected %d listeners, found %d", 2, len(listeners))
	}
	l := listeners[1]
	originalSrcFilterFound := false
	for _, lf := range l.ListenerFilters {
		if lf.Name == xdsfilters.OriginalSrcFilterName {
			originalSrcFilterFound = true
			break
		}
	}
	if !originalSrcFilterFound {
		t.Fatalf("listener filter %s expected", xdsfilters.OriginalSrcFilterName)
	}
}
