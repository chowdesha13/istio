// Copyright Istio Authors. All Rights Reserved.
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
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	http "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	wrappers "google.golang.org/protobuf/types/known/wrapperspb"

	meshconfig "istio.io/api/mesh/v1alpha1"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
	authn_model "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	xdsfilters "istio.io/istio/pilot/pkg/xds/filters"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pilot/test/xdstest"
	istiocluster "istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/host"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/network"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
)

func TestApplyDestinationRule(t *testing.T) {
	servicePort := model.PortList{
		&model.Port{
			Name:     "default",
			Port:     8080,
			Protocol: protocol.HTTP,
		},
		&model.Port{
			Name:     "auto",
			Port:     9090,
			Protocol: protocol.Unsupported,
		},
	}
	service := &model.Service{
		Hostname:   host.Name("foo.default.svc.cluster.local"),
		Ports:      servicePort,
		Resolution: model.ClientSideLB,
		Attributes: model.ServiceAttributes{
			Namespace: TestServiceNamespace,
		},
	}

	cases := []struct {
		name                   string
		cluster                *cluster.Cluster
		clusterMode            ClusterMode
		service                *model.Service
		port                   *model.Port
		proxyView              model.ProxyView
		destRule               *networking.DestinationRule
		expectedSubsetClusters []*cluster.Cluster
	}{
		// TODO(ramaraochavali): Add more tests to cover additional conditions.
		{
			name:                   "nil destination rule",
			cluster:                &cluster.Cluster{},
			clusterMode:            DefaultClusterMode,
			service:                &model.Service{},
			port:                   &model.Port{},
			proxyView:              model.ProxyViewAll,
			destRule:               nil,
			expectedSubsetClusters: []*cluster.Cluster{},
		},
		{
			name:        "destination rule with subsets",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				Subsets: []*networking.Subset{
					{
						Name:   "foobar",
						Labels: map[string]string{"foo": "bar"},
					},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{
				{
					Name:                 "outbound|8080|foobar|foo.default.svc.cluster.local",
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
					EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
						ServiceName: "outbound|8080|foobar|foo.default.svc.cluster.local",
					},
				},
			},
		},
		{
			name:        "destination rule with pass through subsets",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				Subsets: []*networking.Subset{
					{
						Name:   "foobar",
						Labels: map[string]string{"foo": "bar"},
						TrafficPolicy: &networking.TrafficPolicy{
							LoadBalancer: &networking.LoadBalancerSettings{
								LbPolicy: &networking.LoadBalancerSettings_Simple{Simple: networking.LoadBalancerSettings_PASSTHROUGH},
							},
						},
					},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{
				{
					Name:                 "outbound|8080|foobar|foo.default.svc.cluster.local",
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_ORIGINAL_DST},
				},
			},
		},
		{
			name: "destination rule static with pass",
			cluster: &cluster.Cluster{
				Name:                 "foo",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
				LoadAssignment:       &endpoint.ClusterLoadAssignment{},
			},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					LoadBalancer: &networking.LoadBalancerSettings{
						LbPolicy: &networking.LoadBalancerSettings_Simple{Simple: networking.LoadBalancerSettings_PASSTHROUGH},
					},
				},
			},
		},
		{
			name:        "destination rule with subsets for SniDnat cluster",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: SniDnatClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				Subsets: []*networking.Subset{
					{
						Name:   "foobar",
						Labels: map[string]string{"foo": "bar"},
					},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{
				{
					Name:                 "outbound_.8080_.foobar_.foo.default.svc.cluster.local",
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
					EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
						ServiceName: "outbound_.8080_.foobar_.foo.default.svc.cluster.local",
					},
				},
			},
		},
		{
			name:        "destination rule with subset traffic policy",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				Subsets: []*networking.Subset{
					{
						Name:   "foobar",
						Labels: map[string]string{"foo": "bar"},
						TrafficPolicy: &networking.TrafficPolicy{
							ConnectionPool: &networking.ConnectionPoolSettings{
								Http: &networking.ConnectionPoolSettings_HTTPSettings{
									MaxRetries: 10,
								},
							},
						},
					},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{
				{
					Name:                 "outbound|8080|foobar|foo.default.svc.cluster.local",
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
					EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
						ServiceName: "outbound|8080|foobar|foo.default.svc.cluster.local",
					},
					CircuitBreakers: &cluster.CircuitBreakers{
						Thresholds: []*cluster.CircuitBreakers_Thresholds{
							{
								MaxRetries: &wrappers.UInt32Value{
									Value: 10,
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "destination rule with use client protocol traffic policy",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					ConnectionPool: &networking.ConnectionPoolSettings{
						Http: &networking.ConnectionPoolSettings_HTTPSettings{
							MaxRetries:        10,
							UseClientProtocol: true,
						},
					},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{},
		},
		{
			name:        "destination rule with maxRequestsPerConnection",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					ConnectionPool: &networking.ConnectionPoolSettings{
						Http: &networking.ConnectionPoolSettings_HTTPSettings{
							MaxRetries:               10,
							MaxRequestsPerConnection: 10,
						},
					},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{},
		},
		{
			name:        "subset without labels in both",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host:    "foo.example.com",
				Subsets: []*networking.Subset{{Name: "v1"}},
			},
			expectedSubsetClusters: []*cluster.Cluster{{
				Name:                 "outbound|8080|v1|foo.example.com",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			}},
		},
		{
			name:        "subset without labels in dest rule",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
					Labels:    map[string]string{"foo": "bar"},
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host:    "foo.example.com",
				Subsets: []*networking.Subset{{Name: "v1"}},
			},
			expectedSubsetClusters: []*cluster.Cluster{{
				Name:                 "outbound|8080|v1|foo.example.com",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			}},
		},
		{
			name:        "subset with labels in both",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
					Labels:    map[string]string{"foo": "bar"},
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.example.com",
				Subsets: []*networking.Subset{{
					Name:   "v1",
					Labels: map[string]string{"foo": "bar"},
				}},
			},
			expectedSubsetClusters: []*cluster.Cluster{{
				Name:                 "outbound|8080|v1|foo.example.com",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS},
			}},
		},
		{
			name:        "subset with labels in both, not matching",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
					Labels:    map[string]string{"foo": "bar"},
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.example.com",
				Subsets: []*networking.Subset{{
					Name:   "v1",
					Labels: map[string]string{"foo": "not-match"},
				}},
			},
			expectedSubsetClusters: []*cluster.Cluster{},
		},
		{
			name:        "subset without labels in both and resolution of DNS_ROUND_ROBIN",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSRoundRobinLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host:    "foo.example.com",
				Subsets: []*networking.Subset{{Name: "v1"}},
			},
			expectedSubsetClusters: []*cluster.Cluster{{
				Name:                 "outbound|8080|v1|foo.example.com",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
			}},
		},
		{
			name:        "subset without labels in dest rule and a resolution of DNS_ROUND_ROBIN",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSRoundRobinLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
					Labels:    map[string]string{"foo": "bar"},
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host:    "foo.example.com",
				Subsets: []*networking.Subset{{Name: "v1"}},
			},
			expectedSubsetClusters: []*cluster.Cluster{{
				Name:                 "outbound|8080|v1|foo.example.com",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
			}},
		},
		{
			name:        "subset with labels in both",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSRoundRobinLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
					Labels:    map[string]string{"foo": "bar"},
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.example.com",
				Subsets: []*networking.Subset{{
					Name:   "v1",
					Labels: map[string]string{"foo": "bar"},
				}},
			},
			expectedSubsetClusters: []*cluster.Cluster{{
				Name:                 "outbound|8080|v1|foo.example.com",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
			}},
		},
		{
			name:        "subset with labels in both, not matching",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS}},
			clusterMode: DefaultClusterMode,
			service: &model.Service{
				Hostname:   host.Name("foo.example.com"),
				Ports:      servicePort,
				Resolution: model.DNSRoundRobinLB,
				Attributes: model.ServiceAttributes{
					Namespace: TestServiceNamespace,
					Labels:    map[string]string{"foo": "bar"},
				},
			},
			port:      servicePort[0],
			proxyView: model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.example.com",
				Subsets: []*networking.Subset{{
					Name:   "v1",
					Labels: map[string]string{"foo": "not-match"},
				}},
			},
			expectedSubsetClusters: []*cluster.Cluster{},
		},
		{
			name:        "destination rule with tls mode SIMPLE",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{Mode: networking.ClientTLSSettings_SIMPLE},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{},
		},
		{
			name:        "destination rule with tls mode MUTUAL",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{Mode: networking.ClientTLSSettings_MUTUAL},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{},
		},
		{
			name:        "destination rule with tls mode ISTIO_MUTUAL",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{Mode: networking.ClientTLSSettings_ISTIO_MUTUAL},
				},
			},
			expectedSubsetClusters: []*cluster.Cluster{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			instances := []*model.ServiceInstance{
				{
					Service:     tt.service,
					ServicePort: tt.port,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.1",
						EndpointPort: 10001,
						Locality: model.Locality{
							ClusterID: "",
							Label:     "region1/zone1/subzone1",
						},
						Labels:  tt.service.Attributes.Labels,
						TLSMode: model.IstioMutualTLSModeLabel,
					},
				},
			}

			var cfg *config.Config
			if tt.destRule != nil {
				cfg = &config.Config{
					Meta: config.Meta{
						GroupVersionKind: gvk.DestinationRule,
						Name:             "acme",
						Namespace:        "default",
					},
					Spec: tt.destRule,
				}
			}
			cg := NewConfigGenTest(t, TestOptions{
				Instances:      instances,
				ConfigPointers: []*config.Config{cfg},
				Services:       []*model.Service{tt.service},
			})
			cg.MemRegistry.WantGetProxyServiceInstances = instances
			proxy := cg.SetupProxy(nil)
			cb := NewClusterBuilder(proxy, &model.PushRequest{Push: cg.PushContext()}, nil)

			tt.cluster.CommonLbConfig = &cluster.Cluster_CommonLbConfig{}

			ec := newClusterWrapper(tt.cluster)
			destRule := proxy.SidecarScope.DestinationRule(model.TrafficDirectionOutbound, proxy, tt.service.Hostname).GetRule()

			subsetClusters := cb.applyDestinationRule(ec, tt.clusterMode, tt.service, tt.port, tt.proxyView, destRule, nil)
			if len(subsetClusters) != len(tt.expectedSubsetClusters) {
				t.Fatalf("Unexpected subset clusters want %v, got %v. keys=%v",
					len(tt.expectedSubsetClusters), len(subsetClusters), xdstest.MapKeys(xdstest.ExtractClusters(subsetClusters)))
			}
			if len(tt.expectedSubsetClusters) > 0 {
				compareClusters(t, tt.expectedSubsetClusters[0], subsetClusters[0])
			}
			// Validate that use client protocol configures cluster correctly.
			if tt.destRule != nil && tt.destRule.TrafficPolicy != nil && tt.destRule.TrafficPolicy.GetConnectionPool().GetHttp().GetUseClientProtocol() {
				if ec.httpProtocolOptions == nil {
					t.Errorf("Expected cluster %s to have http protocol options but not found", tt.cluster.Name)
				}
				if ec.httpProtocolOptions.UpstreamProtocolOptions == nil &&
					ec.httpProtocolOptions.GetUseDownstreamProtocolConfig() == nil {
					t.Errorf("Expected cluster %s to have downstream protocol options but not found", tt.cluster.Name)
				}
			}

			// Validate that use client protocol configures cluster correctly.
			if tt.destRule != nil && tt.destRule.TrafficPolicy != nil && tt.destRule.TrafficPolicy.GetConnectionPool().GetHttp().GetMaxRequestsPerConnection() > 0 {
				if ec.httpProtocolOptions == nil {
					t.Errorf("Expected cluster %s to have http protocol options but not found", tt.cluster.Name)
				}
				if ec.httpProtocolOptions.CommonHttpProtocolOptions == nil {
					t.Errorf("Expected cluster %s to have common http protocol options but not found", tt.cluster.Name)
				}
				if ec.httpProtocolOptions.CommonHttpProtocolOptions.MaxRequestsPerConnection.GetValue() !=
					uint32(tt.destRule.TrafficPolicy.GetConnectionPool().GetHttp().MaxRequestsPerConnection) {
					t.Errorf("Unexpected max_requests_per_connection found")
				}
			}

			// Validate that alpn_override is correctly configured on cluster given a TLS mode.
			if tt.destRule != nil && tt.destRule.TrafficPolicy != nil && tt.destRule.TrafficPolicy.Tls != nil {
				tlsMode := tt.destRule.TrafficPolicy.Tls.Mode
				if tlsMode == networking.ClientTLSSettings_SIMPLE || tlsMode == networking.ClientTLSSettings_MUTUAL {
					md := tt.cluster.Metadata
					istio, ok := md.FilterMetadata[util.IstioMetadataKey]
					if !ok {
						t.Errorf("Istio metadata not found")
					}
					alpnOverride, found := istio.Fields[util.AlpnOverrideMetadataKey]

					if found {
						if alpnOverride.GetStringValue() != "false" {
							t.Errorf("alpn_override:%s tlsMode:%s, should be false for either TLS mode SIMPLE or MUTUAL", alpnOverride, tlsMode)
						}
					} else {
						t.Errorf("alpn_override metadata should be written for either TLS mode SIMPLE or MUTUAL")
					}
				} else {
					// If TLS settings are not found, alpn_override metadata should not be written
					md := tt.cluster.Metadata
					istio, ok := md.FilterMetadata[util.IstioMetadataKey]
					if ok {
						alpnOverride, found := istio.Fields[util.AlpnOverrideMetadataKey]
						if found {
							// nolint: lll
							t.Errorf("alpn_override:%s tlsMode:%s, alpn_override metadata should not be written if TLS mode is neither SIMPLE nor MUTUAL", alpnOverride.GetStringValue(), tlsMode)
						}

					}
				}

			}

			// Validate that ORIGINAL_DST cluster does not have load assignments
			for _, subset := range subsetClusters {
				if subset.GetType() == cluster.Cluster_ORIGINAL_DST && subset.GetLoadAssignment() != nil {
					t.Errorf("Passthrough subsets should not have load assignments")
				}
			}
			if ec.cluster.GetType() == cluster.Cluster_ORIGINAL_DST && ec.cluster.GetLoadAssignment() != nil {
				t.Errorf("Passthrough should not have load assignments")
			}
		})
	}
}

func compareClusters(t *testing.T, ec *cluster.Cluster, gc *cluster.Cluster) {
	// TODO(ramaraochavali): Expand the comparison to more fields.
	t.Helper()
	if ec.Name != gc.Name {
		t.Errorf("Unexpected cluster name want %s, got %s", ec.Name, gc.Name)
	}
	if ec.GetType() != gc.GetType() {
		t.Errorf("Unexpected cluster discovery type want %v, got %v", ec.GetType(), gc.GetType())
	}
	if ec.GetType() == cluster.Cluster_EDS && ec.EdsClusterConfig.ServiceName != gc.EdsClusterConfig.ServiceName {
		t.Errorf("Unexpected service name in EDS config want %v, got %v", ec.EdsClusterConfig.ServiceName, gc.EdsClusterConfig.ServiceName)
	}
	if ec.CircuitBreakers != nil {
		if ec.CircuitBreakers.Thresholds[0].MaxRetries.Value != gc.CircuitBreakers.Thresholds[0].MaxRetries.Value {
			t.Errorf("Unexpected circuit breaker thresholds want %v, got %v", ec.CircuitBreakers.Thresholds[0].MaxRetries, gc.CircuitBreakers.Thresholds[0].MaxRetries)
		}
	}
}

func TestMergeTrafficPolicy(t *testing.T) {
	cases := []struct {
		name     string
		original *networking.TrafficPolicy
		subset   *networking.TrafficPolicy
		port     *model.Port
		expected *networking.TrafficPolicy
	}{
		{
			name:     "all nil policies",
			original: nil,
			subset:   nil,
			port:     nil,
			expected: nil,
		},
		{
			name: "no subset policy",
			original: &networking.TrafficPolicy{
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
			},
			subset: nil,
			port:   nil,
			expected: &networking.TrafficPolicy{
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
			},
		},
		{
			name:     "no parent policy",
			original: nil,
			subset: &networking.TrafficPolicy{
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
			},
			port: nil,
			expected: &networking.TrafficPolicy{
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
			},
		},
		{
			name: "merge non-conflicting fields",
			original: &networking.TrafficPolicy{
				Tls: &networking.ClientTLSSettings{
					Mode: networking.ClientTLSSettings_ISTIO_MUTUAL,
				},
			},
			subset: &networking.TrafficPolicy{
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
			},
			port: nil,
			expected: &networking.TrafficPolicy{
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
				Tls: &networking.ClientTLSSettings{
					Mode: networking.ClientTLSSettings_ISTIO_MUTUAL,
				},
			},
		},
		{
			name: "subset overwrite top-level fields",
			original: &networking.TrafficPolicy{
				Tls: &networking.ClientTLSSettings{
					Mode: networking.ClientTLSSettings_ISTIO_MUTUAL,
				},
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
			},
			subset: &networking.TrafficPolicy{
				Tls: &networking.ClientTLSSettings{
					Mode: networking.ClientTLSSettings_SIMPLE,
				},
			},
			port: nil,
			expected: &networking.TrafficPolicy{
				Tls: &networking.ClientTLSSettings{
					Mode: networking.ClientTLSSettings_SIMPLE,
				},
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
			},
		},
		{
			name:     "merge port level policy, and do not inherit top-level fields",
			original: nil,
			subset: &networking.TrafficPolicy{
				LoadBalancer: &networking.LoadBalancerSettings{
					LbPolicy: &networking.LoadBalancerSettings_Simple{
						Simple: networking.LoadBalancerSettings_ROUND_ROBIN,
					},
				},
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
				PortLevelSettings: []*networking.TrafficPolicy_PortTrafficPolicy{
					{
						Port: &networking.PortSelector{
							Number: 8080,
						},
						LoadBalancer: &networking.LoadBalancerSettings{
							LbPolicy: &networking.LoadBalancerSettings_Simple{
								Simple: networking.LoadBalancerSettings_LEAST_REQUEST,
							},
						},
					},
				},
			},
			port: &model.Port{Port: 8080},
			expected: &networking.TrafficPolicy{
				LoadBalancer: &networking.LoadBalancerSettings{
					LbPolicy: &networking.LoadBalancerSettings_Simple{
						Simple: networking.LoadBalancerSettings_LEAST_REQUEST,
					},
				},
			},
		},
		{
			name: "merge port level policy, and do not inherit top-level fields",
			original: &networking.TrafficPolicy{
				LoadBalancer: &networking.LoadBalancerSettings{
					LbPolicy: &networking.LoadBalancerSettings_Simple{
						Simple: networking.LoadBalancerSettings_ROUND_ROBIN,
					},
				},
				OutlierDetection: &networking.OutlierDetection{
					ConsecutiveErrors: 20,
				},
				PortLevelSettings: []*networking.TrafficPolicy_PortTrafficPolicy{
					{
						Port: &networking.PortSelector{
							Number: 8080,
						},
						OutlierDetection: &networking.OutlierDetection{
							ConsecutiveErrors: 15,
						},
					},
				},
			},
			subset: &networking.TrafficPolicy{
				LoadBalancer: &networking.LoadBalancerSettings{
					LbPolicy: &networking.LoadBalancerSettings_Simple{
						Simple: networking.LoadBalancerSettings_ROUND_ROBIN,
					},
				},
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
				PortLevelSettings: []*networking.TrafficPolicy_PortTrafficPolicy{
					{
						Port: &networking.PortSelector{
							Number: 8080,
						},
						OutlierDetection: &networking.OutlierDetection{
							ConsecutiveErrors: 13,
						},
					},
				},
			},
			port: &model.Port{Port: 8080},
			expected: &networking.TrafficPolicy{
				OutlierDetection: &networking.OutlierDetection{
					ConsecutiveErrors: 13,
				},
			},
		},
		{
			name: "default cluster, non-matching port selector",
			original: &networking.TrafficPolicy{
				LoadBalancer: &networking.LoadBalancerSettings{
					LbPolicy: &networking.LoadBalancerSettings_Simple{
						Simple: networking.LoadBalancerSettings_ROUND_ROBIN,
					},
				},
				OutlierDetection: &networking.OutlierDetection{
					ConsecutiveErrors: 20,
				},
				PortLevelSettings: []*networking.TrafficPolicy_PortTrafficPolicy{
					{
						Port: &networking.PortSelector{
							Number: 8080,
						},
						OutlierDetection: &networking.OutlierDetection{
							ConsecutiveErrors: 15,
						},
					},
				},
			},
			subset: &networking.TrafficPolicy{
				LoadBalancer: &networking.LoadBalancerSettings{
					LbPolicy: &networking.LoadBalancerSettings_Simple{
						Simple: networking.LoadBalancerSettings_ROUND_ROBIN,
					},
				},
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
				PortLevelSettings: []*networking.TrafficPolicy_PortTrafficPolicy{
					{
						Port: &networking.PortSelector{
							Number: 8080,
						},
						OutlierDetection: &networking.OutlierDetection{
							ConsecutiveErrors: 13,
						},
					},
				},
			},
			port: &model.Port{Port: 9090},
			expected: &networking.TrafficPolicy{
				LoadBalancer: &networking.LoadBalancerSettings{
					LbPolicy: &networking.LoadBalancerSettings_Simple{
						Simple: networking.LoadBalancerSettings_ROUND_ROBIN,
					},
				},
				ConnectionPool: &networking.ConnectionPoolSettings{
					Http: &networking.ConnectionPoolSettings_HTTPSettings{
						MaxRetries: 10,
					},
				},
				OutlierDetection: &networking.OutlierDetection{
					ConsecutiveErrors: 20,
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			policy := MergeTrafficPolicy(tt.original, tt.subset, tt.port)
			assert.Equal(t, policy, tt.expected)
		})
	}
}

func TestApplyEdsConfig(t *testing.T) {
	cases := []struct {
		name      string
		cluster   *cluster.Cluster
		edsConfig *cluster.Cluster_EdsClusterConfig
	}{
		{
			name:      "non eds type of cluster",
			cluster:   &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STRICT_DNS}},
			edsConfig: nil,
		},
		{
			name:    "eds type of cluster",
			cluster: &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			edsConfig: &cluster.Cluster_EdsClusterConfig{
				ServiceName: "foo",
				EdsConfig: &core.ConfigSource{
					ConfigSourceSpecifier: &core.ConfigSource_Ads{
						Ads: &core.AggregatedConfigSource{},
					},
					InitialFetchTimeout: durationpb.New(0),
					ResourceApiVersion:  core.ApiVersion_V3,
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			maybeApplyEdsConfig(tt.cluster)
			if !reflect.DeepEqual(tt.cluster.EdsClusterConfig, tt.edsConfig) {
				t.Errorf("Unexpected Eds config in cluster. want %v, got %v", tt.edsConfig, tt.cluster.EdsClusterConfig)
			}
		})
	}
}

func TestBuildDefaultCluster(t *testing.T) {
	servicePort := &model.Port{
		Name:     "default",
		Port:     8080,
		Protocol: protocol.HTTP,
	}

	cases := []struct {
		name            string
		clusterName     string
		discovery       cluster.Cluster_DiscoveryType
		endpoints       []*endpoint.LocalityLbEndpoints
		direction       model.TrafficDirection
		external        bool
		expectedCluster *cluster.Cluster
	}{
		{
			name:        "default EDS cluster",
			clusterName: "foo",
			discovery:   cluster.Cluster_EDS,
			endpoints:   nil,
			direction:   model.TrafficDirectionOutbound,
			external:    false,
			expectedCluster: &cluster.Cluster{
				Name:                 "foo",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
				CommonLbConfig:       &cluster.Cluster_CommonLbConfig{},
				ConnectTimeout:       &durationpb.Duration{Seconds: 10, Nanos: 1},
				CircuitBreakers: &cluster.CircuitBreakers{
					Thresholds: []*cluster.CircuitBreakers_Thresholds{getDefaultCircuitBreakerThresholds()},
				},
				Filters:  []*cluster.Filter{xdsfilters.TCPClusterMx},
				LbPolicy: defaultLBAlgorithm(),
				Metadata: &core.Metadata{
					FilterMetadata: map[string]*structpb.Struct{
						util.IstioMetadataKey: {
							Fields: map[string]*structpb.Value{
								"services": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
									{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
										"host": {
											Kind: &structpb.Value_StringValue{
												StringValue: "host",
											},
										},
										"name": {
											Kind: &structpb.Value_StringValue{
												StringValue: "svc",
											},
										},
										"namespace": {
											Kind: &structpb.Value_StringValue{
												StringValue: "default",
											},
										},
									}}}},
								}}}},
							},
						},
					},
				},
				EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
					ServiceName: "foo",
					EdsConfig: &core.ConfigSource{
						ConfigSourceSpecifier: &core.ConfigSource_Ads{
							Ads: &core.AggregatedConfigSource{},
						},
						InitialFetchTimeout: durationpb.New(0),
						ResourceApiVersion:  core.ApiVersion_V3,
					},
				},
			},
		},
		{
			name:            "static cluster with no endpoints",
			clusterName:     "foo",
			discovery:       cluster.Cluster_STATIC,
			endpoints:       nil,
			direction:       model.TrafficDirectionOutbound,
			external:        false,
			expectedCluster: nil,
		},
		{
			name:            "strict DNS cluster with no endpoints",
			clusterName:     "foo",
			discovery:       cluster.Cluster_STRICT_DNS,
			endpoints:       nil,
			direction:       model.TrafficDirectionOutbound,
			external:        false,
			expectedCluster: nil,
		},
		{
			name:        "static cluster with endpoints",
			clusterName: "foo",
			discovery:   cluster.Cluster_STATIC,
			endpoints: []*endpoint.LocalityLbEndpoints{
				{
					Locality: &core.Locality{
						Region:  "region1",
						Zone:    "zone1",
						SubZone: "subzone1",
					},
					LbEndpoints: []*endpoint.LbEndpoint{},
					LoadBalancingWeight: &wrappers.UInt32Value{
						Value: 1,
					},
					Priority: 0,
				},
			},
			direction: model.TrafficDirectionOutbound,
			external:  false,
			expectedCluster: &cluster.Cluster{
				Name:                 "foo",
				ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_STATIC},
				CommonLbConfig:       &cluster.Cluster_CommonLbConfig{},
				ConnectTimeout:       &durationpb.Duration{Seconds: 10, Nanos: 1},
				Filters:              []*cluster.Filter{xdsfilters.TCPClusterMx},
				LbPolicy:             defaultLBAlgorithm(),
				LoadAssignment: &endpoint.ClusterLoadAssignment{
					ClusterName: "foo",
					Endpoints: []*endpoint.LocalityLbEndpoints{
						{
							Locality: &core.Locality{
								Region:  "region1",
								Zone:    "zone1",
								SubZone: "subzone1",
							},
							LbEndpoints: []*endpoint.LbEndpoint{},
							LoadBalancingWeight: &wrappers.UInt32Value{
								Value: 1,
							},
							Priority: 0,
						},
					},
				},
				CircuitBreakers: &cluster.CircuitBreakers{
					Thresholds: []*cluster.CircuitBreakers_Thresholds{getDefaultCircuitBreakerThresholds()},
				},
				Metadata: &core.Metadata{
					FilterMetadata: map[string]*structpb.Struct{
						util.IstioMetadataKey: {Fields: map[string]*structpb.Value{
							"services": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
								{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{Fields: map[string]*structpb.Value{
									"host": {
										Kind: &structpb.Value_StringValue{
											StringValue: "host",
										},
									},
									"name": {
										Kind: &structpb.Value_StringValue{
											StringValue: "svc",
										},
									},
									"namespace": {
										Kind: &structpb.Value_StringValue{
											StringValue: "default",
										},
									},
								}}}},
							}}}},
						}},
					},
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			mesh := testMesh()
			cg := NewConfigGenTest(t, TestOptions{MeshConfig: mesh})
			cb := NewClusterBuilder(cg.SetupProxy(nil), &model.PushRequest{Push: cg.PushContext()}, nil)
			service := &model.Service{
				Ports: model.PortList{
					servicePort,
				},
				Hostname:     "host",
				MeshExternal: false,
				Attributes:   model.ServiceAttributes{Name: "svc", Namespace: "default"},
			}
			defaultCluster := cb.buildCluster(tt.clusterName, tt.discovery, tt.endpoints, tt.direction, servicePort, service, nil)
			if defaultCluster != nil {
				_ = cb.applyDestinationRule(defaultCluster, DefaultClusterMode, service, servicePort, cb.proxyView, nil, nil)
			}

			if diff := cmp.Diff(defaultCluster.build(), tt.expectedCluster, protocmp.Transform()); diff != "" {
				t.Errorf("Unexpected default cluster, diff: %v", diff)
			}
		})
	}
}

func TestBuildLocalityLbEndpoints(t *testing.T) {
	proxy := &model.Proxy{
		Metadata: &model.NodeMetadata{
			ClusterID: "cluster-1",
		},
	}
	servicePort := &model.Port{
		Name:     "default",
		Port:     8080,
		Protocol: protocol.HTTP,
	}
	service := &model.Service{
		Hostname: host.Name("*.example.org"),
		Ports:    model.PortList{servicePort},
		Attributes: model.ServiceAttributes{
			Name:      "TestService",
			Namespace: "test-ns",
		},
	}

	buildMetadata := func(networkID network.ID, tlsMode, workloadname, namespace string,
		clusterID istiocluster.ID, lbls labels.Instance,
	) *core.Metadata {
		newmeta := &core.Metadata{}
		util.AppendLbEndpointMetadata(&model.EndpointMetadata{
			Network:      networkID,
			TLSMode:      tlsMode,
			WorkloadName: workloadname,
			Namespace:    namespace,
			ClusterID:    clusterID,
			Labels:       lbls,
		}, newmeta)
		return newmeta
	}

	cases := []struct {
		name      string
		mesh      *meshconfig.MeshConfig
		labels    labels.Instance
		instances []*model.ServiceInstance
		expected  []*endpoint.LocalityLbEndpoints
	}{
		{
			name: "basics",
			mesh: testMesh(),
			instances: []*model.ServiceInstance{
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.1",
						EndpointPort: 10001,
						WorkloadName: "workload-1",
						Namespace:    "namespace-1",
						Locality: model.Locality{
							ClusterID: "cluster-1",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
						Network:  "nw-0",
					},
				},
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.2",
						EndpointPort: 10001,
						WorkloadName: "workload-2",
						Namespace:    "namespace-2",
						Locality: model.Locality{
							ClusterID: "cluster-2",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
						Network:  "nw-1",
					},
				},
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.3",
						EndpointPort: 10001,
						WorkloadName: "workload-3",
						Namespace:    "namespace-3",
						Locality: model.Locality{
							ClusterID: "cluster-3",
							Label:     "region2/zone1/subzone1",
						},
						LbWeight: 40,
						Network:  "",
					},
				},
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.4",
						EndpointPort: 10001,
						WorkloadName: "workload-1",
						Namespace:    "namespace-1",
						Locality: model.Locality{
							ClusterID: "cluster-1",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
						Network:  "filtered-out",
					},
				},
			},
			expected: []*endpoint.LocalityLbEndpoints{
				{
					Locality: &core.Locality{
						Region:  "region1",
						Zone:    "zone1",
						SubZone: "subzone1",
					},
					LoadBalancingWeight: &wrappers.UInt32Value{
						Value: 60,
					},
					LbEndpoints: []*endpoint.LbEndpoint{
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: &core.Address{
										Address: &core.Address_SocketAddress{
											SocketAddress: &core.SocketAddress{
												Address: "192.168.1.1",
												PortSpecifier: &core.SocketAddress_PortValue{
													PortValue: 10001,
												},
											},
										},
									},
								},
							},
							Metadata: buildMetadata("nw-0", "", "workload-1", "namespace-1", "cluster-1", map[string]string{}),
							LoadBalancingWeight: &wrappers.UInt32Value{
								Value: 30,
							},
						},
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: &core.Address{
										Address: &core.Address_SocketAddress{
											SocketAddress: &core.SocketAddress{
												Address: "192.168.1.2",
												PortSpecifier: &core.SocketAddress_PortValue{
													PortValue: 10001,
												},
											},
										},
									},
								},
							},
							Metadata: buildMetadata("nw-1", "", "workload-2", "namespace-2", "cluster-2", map[string]string{}),
							LoadBalancingWeight: &wrappers.UInt32Value{
								Value: 30,
							},
						},
					},
				},
				{
					Locality: &core.Locality{
						Region:  "region2",
						Zone:    "zone1",
						SubZone: "subzone1",
					},
					LoadBalancingWeight: &wrappers.UInt32Value{
						Value: 40,
					},
					LbEndpoints: []*endpoint.LbEndpoint{
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: &core.Address{
										Address: &core.Address_SocketAddress{
											SocketAddress: &core.SocketAddress{
												Address: "192.168.1.3",
												PortSpecifier: &core.SocketAddress_PortValue{
													PortValue: 10001,
												},
											},
										},
									},
								},
							},
							Metadata: buildMetadata("", "", "workload-3", "namespace-3", "cluster-3", map[string]string{}),
							LoadBalancingWeight: &wrappers.UInt32Value{
								Value: 40,
							},
						},
					},
				},
			},
		},
		{
			name: "cluster local",
			mesh: withClusterLocalHosts(testMesh(), "*.example.org"),
			instances: []*model.ServiceInstance{
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.1",
						EndpointPort: 10001,
						Locality: model.Locality{
							ClusterID: "cluster-1",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
					},
				},
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.2",
						EndpointPort: 10001,
						Locality: model.Locality{
							ClusterID: "cluster-2",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
					},
				},
			},
			expected: []*endpoint.LocalityLbEndpoints{
				{
					Locality: &core.Locality{
						Region:  "region1",
						Zone:    "zone1",
						SubZone: "subzone1",
					},
					LoadBalancingWeight: &wrappers.UInt32Value{
						Value: 30,
					},
					LbEndpoints: []*endpoint.LbEndpoint{
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: &core.Address{
										Address: &core.Address_SocketAddress{
											SocketAddress: &core.SocketAddress{
												Address: "192.168.1.1",
												PortSpecifier: &core.SocketAddress_PortValue{
													PortValue: 10001,
												},
											},
										},
									},
								},
							},
							Metadata: buildMetadata("", "", "", "", "cluster-1", map[string]string{}),
							LoadBalancingWeight: &wrappers.UInt32Value{
								Value: 30,
							},
						},
					},
				},
			},
		},
		{
			name:   "subset cluster endpoints with labels",
			mesh:   testMesh(),
			labels: labels.Instance{"version": "v1"},
			instances: []*model.ServiceInstance{
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.1",
						EndpointPort: 10001,
						WorkloadName: "workload-1",
						Namespace:    "namespace-1",
						Labels: map[string]string{
							"version": "v1",
							"app":     "example",
						},
						Locality: model.Locality{
							ClusterID: "cluster-1",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
						Network:  "nw-0",
					},
				},
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.2",
						EndpointPort: 10001,
						WorkloadName: "workload-2",
						Namespace:    "namespace-2",
						Labels: map[string]string{
							"version": "v2",
							"app":     "example",
						},
						Locality: model.Locality{
							ClusterID: "cluster-2",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
						Network:  "nw-1",
					},
				},
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.3",
						EndpointPort: 10001,
						WorkloadName: "workload-3",
						Namespace:    "namespace-3",
						Labels: map[string]string{
							"version": "v3",
							"app":     "example",
						},
						Locality: model.Locality{
							ClusterID: "cluster-3",
							Label:     "region2/zone1/subzone1",
						},
						LbWeight: 40,
						Network:  "",
					},
				},
				{
					Service:     service,
					ServicePort: servicePort,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.4",
						EndpointPort: 10001,
						WorkloadName: "workload-1",
						Namespace:    "namespace-1",
						Labels: map[string]string{
							"version": "v4",
							"app":     "example",
						},
						Locality: model.Locality{
							ClusterID: "cluster-1",
							Label:     "region1/zone1/subzone1",
						},
						LbWeight: 30,
						Network:  "filtered-out",
					},
				},
			},
			expected: []*endpoint.LocalityLbEndpoints{
				{
					Locality: &core.Locality{
						Region:  "region1",
						Zone:    "zone1",
						SubZone: "subzone1",
					},
					LoadBalancingWeight: &wrappers.UInt32Value{
						Value: 30,
					},
					LbEndpoints: []*endpoint.LbEndpoint{
						{
							HostIdentifier: &endpoint.LbEndpoint_Endpoint{
								Endpoint: &endpoint.Endpoint{
									Address: &core.Address{
										Address: &core.Address_SocketAddress{
											SocketAddress: &core.SocketAddress{
												Address: "192.168.1.1",
												PortSpecifier: &core.SocketAddress_PortValue{
													PortValue: 10001,
												},
											},
										},
									},
								},
							},
							Metadata: buildMetadata("nw-0", "", "workload-1", "namespace-1", "cluster-1", map[string]string{
								"version": "v1",
								"app":     "example",
							}),
							LoadBalancingWeight: &wrappers.UInt32Value{
								Value: 30,
							},
						},
					},
				},
			},
		},
	}

	sortEndpoints := func(endpoints []*endpoint.LocalityLbEndpoints) {
		sort.SliceStable(endpoints, func(i, j int) bool {
			if strings.Compare(endpoints[i].Locality.Region, endpoints[j].Locality.Region) < 0 {
				return true
			}
			if strings.Compare(endpoints[i].Locality.Zone, endpoints[j].Locality.Zone) < 0 {
				return true
			}
			return strings.Compare(endpoints[i].Locality.SubZone, endpoints[j].Locality.SubZone) < 0
		})
	}

	for _, tt := range cases {
		for _, resolution := range []model.Resolution{model.DNSLB, model.DNSRoundRobinLB} {
			t.Run(fmt.Sprintf("%s_%s", tt.name, resolution), func(t *testing.T) {
				service.Resolution = resolution
				cg := NewConfigGenTest(t, TestOptions{
					MeshConfig: tt.mesh,
					Services:   []*model.Service{service},
					Instances:  tt.instances,
				})

				cb := NewClusterBuilder(cg.SetupProxy(proxy), &model.PushRequest{Push: cg.PushContext()}, nil)
				view := (&model.Proxy{
					Metadata: &model.NodeMetadata{
						RequestedNetworkView: []string{"nw-0", "nw-1"},
					},
				}).GetView()
				actual := cb.buildLocalityLbEndpoints(view, service, 8080, tt.labels)
				sortEndpoints(actual)
				if v := cmp.Diff(tt.expected, actual, protocmp.Transform()); v != "" {
					t.Fatalf("Expected (-) != actual (+):\n%s", v)
				}
			})
		}
	}
}

func TestConcurrentBuildLocalityLbEndpoints(t *testing.T) {
	test.SetForTest(t, &features.CanonicalServiceForMeshExternalServiceEntry, true)
	proxy := &model.Proxy{
		Metadata: &model.NodeMetadata{
			ClusterID: "cluster-1",
		},
	}
	servicePort := &model.Port{
		Name:     "default",
		Port:     8080,
		Protocol: protocol.HTTP,
	}
	service := &model.Service{
		Hostname: host.Name("*.example.org"),
		Ports:    model.PortList{servicePort},
		Attributes: model.ServiceAttributes{
			Name:      "TestService",
			Namespace: "test-ns",
			Labels:    map[string]string{"service.istio.io/canonical-name": "example-service"},
		},
		MeshExternal: true,
		Resolution:   model.DNSLB,
	}

	buildMetadata := func(networkID network.ID, tlsMode, workloadname, namespace string,
		clusterID istiocluster.ID, lbls labels.Instance,
	) *core.Metadata {
		newmeta := &core.Metadata{}
		util.AppendLbEndpointMetadata(&model.EndpointMetadata{
			Network:      networkID,
			TLSMode:      tlsMode,
			WorkloadName: workloadname,
			Namespace:    namespace,
			ClusterID:    clusterID,
			Labels:       lbls,
		}, newmeta)
		return newmeta
	}

	lbls := labels.Instance{"version": "v1"}

	instances := []*model.ServiceInstance{
		{
			Service:     service,
			ServicePort: servicePort,
			Endpoint: &model.IstioEndpoint{
				Address:      "192.168.1.1",
				EndpointPort: 10001,
				WorkloadName: "workload-1",
				Namespace:    "namespace-1",
				Labels: map[string]string{
					"version": "v1",
					"app":     "example",
				},
				Locality: model.Locality{
					ClusterID: "cluster-1",
					Label:     "region1/zone1/subzone1",
				},
				LbWeight: 30,
				Network:  "nw-0",
			},
		},
		{
			Service:     service,
			ServicePort: servicePort,
			Endpoint: &model.IstioEndpoint{
				Address:      "192.168.1.2",
				EndpointPort: 10001,
				WorkloadName: "workload-2",
				Namespace:    "namespace-2",
				Labels: map[string]string{
					"version": "v2",
					"app":     "example",
				},
				Locality: model.Locality{
					ClusterID: "cluster-2",
					Label:     "region1/zone1/subzone1",
				},
				LbWeight: 30,
				Network:  "nw-1",
			},
		},
		{
			Service:     service,
			ServicePort: servicePort,
			Endpoint: &model.IstioEndpoint{
				Address:      "192.168.1.3",
				EndpointPort: 10001,
				WorkloadName: "workload-3",
				Namespace:    "namespace-3",
				Labels: map[string]string{
					"version": "v3",
					"app":     "example",
				},
				Locality: model.Locality{
					ClusterID: "cluster-3",
					Label:     "region2/zone1/subzone1",
				},
				LbWeight: 40,
				Network:  "",
			},
		},
		{
			Service:     service,
			ServicePort: servicePort,
			Endpoint: &model.IstioEndpoint{
				Address:      "192.168.1.4",
				EndpointPort: 10001,
				WorkloadName: "workload-1",
				Namespace:    "namespace-1",
				Labels: map[string]string{
					"version": "v4",
					"app":     "example",
				},
				Locality: model.Locality{
					ClusterID: "cluster-1",
					Label:     "region1/zone1/subzone1",
				},
				LbWeight: 30,
				Network:  "filtered-out",
			},
		},
	}

	updatedLbls := labels.Instance{
		"app":                                "example",
		model.IstioCanonicalServiceLabelName: "example-service",
	}
	expected := []*endpoint.LocalityLbEndpoints{
		{
			Locality: &core.Locality{
				Region:  "region1",
				Zone:    "zone1",
				SubZone: "subzone1",
			},
			LoadBalancingWeight: &wrappers.UInt32Value{
				Value: 30,
			},
			LbEndpoints: []*endpoint.LbEndpoint{
				{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Address: "192.168.1.1",
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: 10001,
										},
									},
								},
							},
						},
					},
					Metadata: buildMetadata("nw-0", "", "workload-1", "test-ns", "cluster-1", updatedLbls),
					LoadBalancingWeight: &wrappers.UInt32Value{
						Value: 30,
					},
				},
			},
		},
	}

	sortEndpoints := func(endpoints []*endpoint.LocalityLbEndpoints) {
		sort.SliceStable(endpoints, func(i, j int) bool {
			if strings.Compare(endpoints[i].Locality.Region, endpoints[j].Locality.Region) < 0 {
				return true
			}
			if strings.Compare(endpoints[i].Locality.Zone, endpoints[j].Locality.Zone) < 0 {
				return true
			}
			return strings.Compare(endpoints[i].Locality.SubZone, endpoints[j].Locality.SubZone) < 0
		})
	}

	cg := NewConfigGenTest(t, TestOptions{
		MeshConfig: testMesh(),
		Services:   []*model.Service{service},
		Instances:  instances,
	})

	cb := NewClusterBuilder(cg.SetupProxy(proxy), &model.PushRequest{Push: cg.PushContext()}, nil)
	view := (&model.Proxy{
		Metadata: &model.NodeMetadata{
			RequestedNetworkView: []string{"nw-0", "nw-1"},
		},
	}).GetView()
	wg := sync.WaitGroup{}
	wg.Add(5)
	var actual []*endpoint.LocalityLbEndpoints
	mu := sync.Mutex{}
	for i := 0; i < 5; i++ {
		go func() {
			eps := cb.buildLocalityLbEndpoints(view, service, 8080, lbls)
			mu.Lock()
			actual = eps
			mu.Unlock()
			wg.Done()
		}()
	}
	wg.Wait()
	sortEndpoints(actual)
	if v := cmp.Diff(expected, actual, protocmp.Transform()); v != "" {
		t.Fatalf("Expected (-) != actual (+):\n%s", v)
	}
}

func TestBuildPassthroughClusters(t *testing.T) {
	cases := []struct {
		name         string
		ips          []string
		ipv4Expected bool
		ipv6Expected bool
	}{
		{
			name:         "both ipv4 and ipv6",
			ips:          []string{"6.6.6.6", "::1"},
			ipv4Expected: true,
			ipv6Expected: true,
		},
		{
			name:         "ipv4 only",
			ips:          []string{"6.6.6.6"},
			ipv4Expected: true,
			ipv6Expected: false,
		},
		{
			name:         "ipv6 only",
			ips:          []string{"::1"},
			ipv4Expected: false,
			ipv6Expected: true,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			proxy := &model.Proxy{IPAddresses: tt.ips}
			cg := NewConfigGenTest(t, TestOptions{})

			cb := NewClusterBuilder(cg.SetupProxy(proxy), &model.PushRequest{Push: cg.PushContext()}, nil)
			clusters := cb.buildInboundPassthroughClusters()

			var hasIpv4, hasIpv6 bool
			for _, c := range clusters {
				hasIpv4 = hasIpv4 || c.Name == util.InboundPassthroughClusterIpv4
				hasIpv6 = hasIpv6 || c.Name == util.InboundPassthroughClusterIpv6
			}
			if hasIpv4 != tt.ipv4Expected {
				t.Errorf("Unexpected Ipv4 Passthrough Cluster, want %v got %v", tt.ipv4Expected, hasIpv4)
			}
			if hasIpv6 != tt.ipv6Expected {
				t.Errorf("Unexpected Ipv6 Passthrough Cluster, want %v got %v", tt.ipv6Expected, hasIpv6)
			}

			passthrough := xdstest.ExtractCluster(util.InboundPassthroughClusterIpv4, clusters)
			if passthrough == nil {
				passthrough = xdstest.ExtractCluster(util.InboundPassthroughClusterIpv6, clusters)
			}
			// Validate that Passthrough Cluster LB Policy is set correctly.
			if passthrough.GetType() != cluster.Cluster_ORIGINAL_DST || passthrough.GetLbPolicy() != cluster.Cluster_CLUSTER_PROVIDED {
				t.Errorf("Unexpected Discovery type or Lb policy, got Discovery type: %v, Lb Policy: %v", passthrough.GetType(), passthrough.GetLbPolicy())
			}
		})
	}
}

func TestApplyUpstreamTLSSettings(t *testing.T) {
	istioMutualTLSSettings := &networking.ClientTLSSettings{
		Mode:            networking.ClientTLSSettings_ISTIO_MUTUAL,
		SubjectAltNames: []string{"custom.foo.com"},
		Sni:             "custom.foo.com",
	}
	mutualTLSSettingsWithCerts := &networking.ClientTLSSettings{
		Mode:              networking.ClientTLSSettings_MUTUAL,
		CaCertificates:    constants.DefaultRootCert,
		ClientCertificate: constants.DefaultCertChain,
		PrivateKey:        constants.DefaultKey,
		SubjectAltNames:   []string{"custom.foo.com"},
		Sni:               "custom.foo.com",
	}
	simpleTLSSettingsWithCerts := &networking.ClientTLSSettings{
		Mode:            networking.ClientTLSSettings_SIMPLE,
		CaCertificates:  constants.DefaultRootCert,
		SubjectAltNames: []string{"custom.foo.com"},
		Sni:             "custom.foo.com",
	}

	tests := []struct {
		name                       string
		mtlsCtx                    mtlsContextType
		discoveryType              cluster.Cluster_DiscoveryType
		tls                        *networking.ClientTLSSettings
		h2                         bool
		expectTransportSocket      bool
		expectTransportSocketMatch bool

		validateTLSContext func(t *testing.T, ctx *tls.UpstreamTlsContext)
	}{
		{
			name:                       "user specified without tls",
			mtlsCtx:                    userSupplied,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        nil,
			expectTransportSocket:      false,
			expectTransportSocketMatch: false,
		},
		{
			name:                       "user specified with istio_mutual tls",
			mtlsCtx:                    userSupplied,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        istioMutualTLSSettings,
			expectTransportSocket:      true,
			expectTransportSocketMatch: false,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); !reflect.DeepEqual(got, util.ALPNInMeshWithMxc) {
					t.Fatalf("expected alpn list %v; got %v", util.ALPNInMeshWithMxc, got)
				}
			},
		},
		{
			name:                       "user specified with istio_mutual tls with h2",
			mtlsCtx:                    userSupplied,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        istioMutualTLSSettings,
			expectTransportSocket:      true,
			expectTransportSocketMatch: false,
			h2:                         true,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); !reflect.DeepEqual(got, util.ALPNInMeshH2WithMxc) {
					t.Fatalf("expected alpn list %v; got %v", util.ALPNInMeshH2WithMxc, got)
				}
			},
		},
		{
			name:                       "user specified simple tls",
			mtlsCtx:                    userSupplied,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        simpleTLSSettingsWithCerts,
			expectTransportSocket:      true,
			expectTransportSocketMatch: false,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				rootName := "file-root:" + mutualTLSSettingsWithCerts.CaCertificates
				if got := ctx.CommonTlsContext.GetCombinedValidationContext().GetValidationContextSdsSecretConfig().GetName(); rootName != got {
					t.Fatalf("expected root name %v got %v", rootName, got)
				}
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); got != nil {
					t.Fatalf("expected alpn list nil as not h2 or Istio_Mutual TLS Setting; got %v", got)
				}
				if got := ctx.GetSni(); got != simpleTLSSettingsWithCerts.Sni {
					t.Fatalf("expected TLSContext SNI %v; got %v", simpleTLSSettingsWithCerts.Sni, got)
				}
			},
		},
		{
			name:                       "user specified simple tls with h2",
			mtlsCtx:                    userSupplied,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        simpleTLSSettingsWithCerts,
			expectTransportSocket:      true,
			expectTransportSocketMatch: false,
			h2:                         true,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				rootName := "file-root:" + mutualTLSSettingsWithCerts.CaCertificates
				if got := ctx.CommonTlsContext.GetCombinedValidationContext().GetValidationContextSdsSecretConfig().GetName(); rootName != got {
					t.Fatalf("expected root name %v got %v", rootName, got)
				}
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); !reflect.DeepEqual(got, util.ALPNH2Only) {
					t.Fatalf("expected alpn list %v; got %v", util.ALPNH2Only, got)
				}
				if got := ctx.GetSni(); got != simpleTLSSettingsWithCerts.Sni {
					t.Fatalf("expected TLSContext SNI %v; got %v", simpleTLSSettingsWithCerts.Sni, got)
				}
			},
		},
		{
			name:                       "user specified mutual tls",
			mtlsCtx:                    userSupplied,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        mutualTLSSettingsWithCerts,
			expectTransportSocket:      true,
			expectTransportSocketMatch: false,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				rootName := "file-root:" + mutualTLSSettingsWithCerts.CaCertificates
				certName := fmt.Sprintf("file-cert:%s~%s", mutualTLSSettingsWithCerts.ClientCertificate, mutualTLSSettingsWithCerts.PrivateKey)
				if got := ctx.CommonTlsContext.GetCombinedValidationContext().GetValidationContextSdsSecretConfig().GetName(); rootName != got {
					t.Fatalf("expected root name %v got %v", rootName, got)
				}
				if got := ctx.CommonTlsContext.GetTlsCertificateSdsSecretConfigs()[0].GetName(); certName != got {
					t.Fatalf("expected cert name %v got %v", certName, got)
				}
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); got != nil {
					t.Fatalf("expected alpn list nil as not h2 or Istio_Mutual TLS Setting; got %v", got)
				}
				if got := ctx.GetSni(); got != mutualTLSSettingsWithCerts.Sni {
					t.Fatalf("expected TLSContext SNI %v; got %v", mutualTLSSettingsWithCerts.Sni, got)
				}
			},
		},
		{
			name:                       "user specified mutual tls with h2",
			mtlsCtx:                    userSupplied,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        mutualTLSSettingsWithCerts,
			expectTransportSocket:      true,
			expectTransportSocketMatch: false,
			h2:                         true,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				rootName := "file-root:" + mutualTLSSettingsWithCerts.CaCertificates
				certName := fmt.Sprintf("file-cert:%s~%s", mutualTLSSettingsWithCerts.ClientCertificate, mutualTLSSettingsWithCerts.PrivateKey)
				if got := ctx.CommonTlsContext.GetCombinedValidationContext().GetValidationContextSdsSecretConfig().GetName(); rootName != got {
					t.Fatalf("expected root name %v got %v", rootName, got)
				}
				if got := ctx.CommonTlsContext.GetTlsCertificateSdsSecretConfigs()[0].GetName(); certName != got {
					t.Fatalf("expected cert name %v got %v", certName, got)
				}
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); !reflect.DeepEqual(got, util.ALPNH2Only) {
					t.Fatalf("expected alpn list %v; got %v", util.ALPNH2Only, got)
				}
				if got := ctx.GetSni(); got != mutualTLSSettingsWithCerts.Sni {
					t.Fatalf("expected TLSContext SNI %v; got %v", mutualTLSSettingsWithCerts.Sni, got)
				}
			},
		},
		{
			name:                       "auto detect with tls",
			mtlsCtx:                    autoDetected,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        istioMutualTLSSettings,
			expectTransportSocket:      false,
			expectTransportSocketMatch: true,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); !reflect.DeepEqual(got, util.ALPNInMeshWithMxc) {
					t.Fatalf("expected alpn list %v; got %v", util.ALPNInMeshWithMxc, got)
				}
			},
		},
		{
			name:                       "auto detect with tls and h2 options",
			mtlsCtx:                    autoDetected,
			discoveryType:              cluster.Cluster_EDS,
			tls:                        istioMutualTLSSettings,
			expectTransportSocket:      false,
			expectTransportSocketMatch: true,
			h2:                         true,
			validateTLSContext: func(t *testing.T, ctx *tls.UpstreamTlsContext) {
				if got := ctx.CommonTlsContext.GetAlpnProtocols(); !reflect.DeepEqual(got, util.ALPNInMeshH2WithMxc) {
					t.Fatalf("expected alpn list %v; got %v", util.ALPNInMeshH2WithMxc, got)
				}
			},
		},
	}

	proxy := &model.Proxy{
		Type:         model.SidecarProxy,
		Metadata:     &model.NodeMetadata{},
		IstioVersion: &model.IstioVersion{Major: 1, Minor: 5},
	}
	push := model.NewPushContext()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cb := NewClusterBuilder(proxy, &model.PushRequest{Push: push}, model.DisabledCache{})
			opts := &buildClusterOpts{
				mutable: newClusterWrapper(&cluster.Cluster{
					ClusterDiscoveryType: &cluster.Cluster_Type{Type: test.discoveryType},
				}),
				mesh: push.Mesh,
			}
			if test.h2 {
				setH2Options(opts.mutable)
			}
			cb.applyUpstreamTLSSettings(opts, test.tls, test.mtlsCtx)

			if test.expectTransportSocket && opts.mutable.cluster.TransportSocket == nil ||
				!test.expectTransportSocket && opts.mutable.cluster.TransportSocket != nil {
				t.Errorf("Expected TransportSocket %v", test.expectTransportSocket)
			}
			if test.expectTransportSocketMatch && opts.mutable.cluster.TransportSocketMatches == nil ||
				!test.expectTransportSocketMatch && opts.mutable.cluster.TransportSocketMatches != nil {
				t.Errorf("Expected TransportSocketMatch %v", test.expectTransportSocketMatch)
			}

			if test.validateTLSContext != nil {
				ctx := &tls.UpstreamTlsContext{}
				if test.expectTransportSocket {
					if err := opts.mutable.cluster.TransportSocket.GetTypedConfig().UnmarshalTo(ctx); err != nil {
						t.Fatal(err)
					}
				} else if test.expectTransportSocketMatch {
					if err := opts.mutable.cluster.TransportSocketMatches[0].TransportSocket.GetTypedConfig().UnmarshalTo(ctx); err != nil {
						t.Fatal(err)
					}
				}
				test.validateTLSContext(t, ctx)
			}
		})
	}
}

type expectedResult struct {
	tlsContext *tls.UpstreamTlsContext
	err        error
}

// TestBuildUpstreamClusterTLSContext tests the buildUpstreamClusterTLSContext function
func TestBuildUpstreamClusterTLSContext(t *testing.T) {
	clientCert := "/path/to/cert"
	rootCert := "path/to/cacert"
	clientKey := "/path/to/key"

	credentialName := "some-fake-credential"

	testCases := []struct {
		name                     string
		opts                     *buildClusterOpts
		tls                      *networking.ClientTLSSettings
		h2                       bool
		router                   bool
		result                   expectedResult
		enableAutoSni            bool
		enableVerifyCertAtClient bool
	}{
		{
			name: "tls mode disabled",
			opts: &buildClusterOpts{
				mutable: newClusterWrapper(&cluster.Cluster{
					Name: "test-cluster",
				}),
			},
			tls: &networking.ClientTLSSettings{
				Mode: networking.ClientTLSSettings_DISABLE,
			},
			result: expectedResult{nil, nil},
		},
		{
			name: "tls mode ISTIO_MUTUAL",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_ISTIO_MUTUAL,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name: "default",
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									InitialFetchTimeout: durationpb.New(time.Second * 0),
									ResourceApiVersion:  core.ApiVersion_V3,
								},
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: "ROOTCA",
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										InitialFetchTimeout: durationpb.New(time.Second * 0),
										ResourceApiVersion:  core.ApiVersion_V3,
									},
								},
							},
						},
						AlpnProtocols: util.ALPNInMeshWithMxc,
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode ISTIO_MUTUAL and H2",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_ISTIO_MUTUAL,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			h2: true,
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name: "default",
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									InitialFetchTimeout: durationpb.New(time.Second * 0),
									ResourceApiVersion:  core.ApiVersion_V3,
								},
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: "ROOTCA",
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										InitialFetchTimeout: durationpb.New(time.Second * 0),
										ResourceApiVersion:  core.ApiVersion_V3,
									},
								},
							},
						},
						AlpnProtocols: util.ALPNInMeshH2WithMxc,
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with no certs specified in tls",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with AutoSni enabled and no sni specified in tls",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				SubjectAltNames: []string{"SAN"},
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
					},
				},
				err: nil,
			},
			enableAutoSni: true,
		},
		{
			name: "tls mode SIMPLE, with AutoSni enabled and sni specified in tls",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
			enableAutoSni: true,
		},
		{
			name: "tls mode SIMPLE, with VerifyCert and AutoSni enabled with SubjectAltNames set",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
			enableAutoSni:            true,
			enableVerifyCertAtClient: true,
		},
		{
			name: "tls mode SIMPLE, with VerifyCert and AutoSni enabled without SubjectAltNames set",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode: networking.ClientTLSSettings_SIMPLE,
				Sni:  "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
			enableAutoSni:            true,
			enableVerifyCertAtClient: true,
		},
		{
			name: "tls mode SIMPLE, with certs specified in tls",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				CaCertificates:  rootCert,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: fmt.Sprintf("file-root:%s", rootCert),
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										ResourceApiVersion: core.ApiVersion_V3,
									},
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with certs specified in tls with h2",
			opts: &buildClusterOpts{
				mutable: newH2TestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				CaCertificates:  rootCert,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			h2: true,
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: fmt.Sprintf("file-root:%s", rootCert),
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										ResourceApiVersion: core.ApiVersion_V3,
									},
								},
							},
						},
						AlpnProtocols: util.ALPNH2Only,
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with certs specified in tls",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				CaCertificates:  rootCert,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: fmt.Sprintf("file-root:%s", rootCert),
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										ResourceApiVersion: core.ApiVersion_V3,
									},
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with SANs specified in service entries",
			opts: &buildClusterOpts{
				mutable:         newTestCluster(),
				serviceAccounts: []string{"se-san.com"},
				serviceRegistry: provider.External,
			},
			tls: &networking.ClientTLSSettings{
				Mode:           networking.ClientTLSSettings_SIMPLE,
				CaCertificates: rootCert,
				Sni:            "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"se-san.com"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: fmt.Sprintf("file-root:%s", rootCert),
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										ResourceApiVersion: core.ApiVersion_V3,
									},
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode MUTUAL, with no client certificate",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_MUTUAL,
				ClientCertificate: "",
				PrivateKey:        "some-fake-key",
			},
			result: expectedResult{
				nil,
				fmt.Errorf("client cert must be provided"),
			},
		},
		{
			name: "tls mode MUTUAL, with no client key",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_MUTUAL,
				ClientCertificate: "some-fake-cert",
				PrivateKey:        "",
			},
			result: expectedResult{
				nil,
				fmt.Errorf("client key must be provided"),
			},
		},
		{
			name: "tls mode MUTUAL, with node metadata sdsEnabled true no root CA specified",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_MUTUAL,
				ClientCertificate: clientCert,
				PrivateKey:        clientKey,
				SubjectAltNames:   []string{"SAN"},
				Sni:               "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name: fmt.Sprintf("file-cert:%s~%s", clientCert, clientKey),
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									ResourceApiVersion: core.ApiVersion_V3,
								},
							},
						},
						ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode MUTUAL, with node metadata sdsEnabled true",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_MUTUAL,
				ClientCertificate: clientCert,
				PrivateKey:        clientKey,
				CaCertificates:    rootCert,
				SubjectAltNames:   []string{"SAN"},
				Sni:               "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name: fmt.Sprintf("file-cert:%s~%s", clientCert, clientKey),
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									ResourceApiVersion: core.ApiVersion_V3,
								},
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: fmt.Sprintf("file-root:%s", rootCert),
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										ResourceApiVersion: core.ApiVersion_V3,
									},
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with CredentialName specified",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				CredentialName:  credentialName,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			router: true,
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{
									MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"}),
								},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with CredentialName specified with h2 and no SAN",
			opts: &buildClusterOpts{
				mutable: newH2TestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:           networking.ClientTLSSettings_SIMPLE,
				CredentialName: credentialName,
				Sni:            "some-sni.com",
			},
			h2:     true,
			router: true,
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
						AlpnProtocols: util.ALPNH2Only,
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode MUTUAL, with CredentialName specified",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_MUTUAL,
				CredentialName:  credentialName,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			router: true,
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name:      "kubernetes://" + credentialName,
								SdsConfig: authn_model.SDSAdsConfig,
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{
									MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"}),
								},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode MUTUAL, with CredentialName specified with h2 and no SAN",
			opts: &buildClusterOpts{
				mutable: newH2TestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:           networking.ClientTLSSettings_MUTUAL,
				CredentialName: credentialName,
				Sni:            "some-sni.com",
			},
			h2:     true,
			router: true,
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name:      "kubernetes://" + credentialName,
								SdsConfig: authn_model.SDSAdsConfig,
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
						AlpnProtocols: util.ALPNH2Only,
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode MUTUAL, credentialName is set with proxy type Sidecar",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:           networking.ClientTLSSettings_MUTUAL,
				CredentialName: "fake-cred",
			},
			result: expectedResult{
				nil,
				nil,
			},
		},
		{
			name: "tls mode SIMPLE, credentialName is set with proxy type Sidecar",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
			},
			tls: &networking.ClientTLSSettings{
				Mode:           networking.ClientTLSSettings_SIMPLE,
				CredentialName: "fake-cred",
			},
			result: expectedResult{
				nil,
				nil,
			},
		},
		{
			name: "tls mode SIMPLE, CredentialName is set with proxy type Sidecar and destinationRule has workload Selector",
			opts: &buildClusterOpts{
				mutable:          newTestCluster(),
				isDrWithSelector: true,
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				CredentialName:  credentialName,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{
									MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"}),
								},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode SIMPLE, with EcdhCurves specified in Mesh Config",
			opts: &buildClusterOpts{
				mutable:          newTestCluster(),
				isDrWithSelector: true,
				mesh: &meshconfig.MeshConfig{
					TlsDefaults: &meshconfig.MeshConfig_TLSConfig{
						EcdhCurves: []string{"P-256"},
					},
				},
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_SIMPLE,
				CredentialName:  credentialName,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
							EcdhCurves:                []string{"P-256"},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{
									MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"}),
								},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode MUTUAL, with EcdhCurves specified in Mesh Config",
			opts: &buildClusterOpts{
				mutable:          newTestCluster(),
				isDrWithSelector: true,
				mesh: &meshconfig.MeshConfig{
					TlsDefaults: &meshconfig.MeshConfig_TLSConfig{
						EcdhCurves: []string{"P-256", "P-384"},
					},
				},
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_MUTUAL,
				CredentialName:  credentialName,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
							EcdhCurves:                []string{"P-256", "P-384"},
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name:      "kubernetes://" + credentialName,
								SdsConfig: authn_model.SDSAdsConfig,
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{
									MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"}),
								},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		// ecdh curves from MeshConfig should be ignored for ISTIO_MUTUAL mode
		{
			name: "tls mode ISTIO_MUTUAL with EcdhCurves specified in Mesh Config",
			opts: &buildClusterOpts{
				mutable: newTestCluster(),
				mesh: &meshconfig.MeshConfig{
					TlsDefaults: &meshconfig.MeshConfig_TLSConfig{
						EcdhCurves: []string{"P-256", "P-384"},
					},
				},
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_ISTIO_MUTUAL,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name: "default",
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									InitialFetchTimeout: durationpb.New(time.Second * 0),
									ResourceApiVersion:  core.ApiVersion_V3,
								},
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"})},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name: "ROOTCA",
									SdsConfig: &core.ConfigSource{
										ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
											ApiConfigSource: &core.ApiConfigSource{
												ApiType:                   core.ApiConfigSource_GRPC,
												SetNodeOnFirstMessageOnly: true,
												TransportApiVersion:       core.ApiVersion_V3,
												GrpcServices: []*core.GrpcService{
													{
														TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
															EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
														},
													},
												},
											},
										},
										InitialFetchTimeout: durationpb.New(time.Second * 0),
										ResourceApiVersion:  core.ApiVersion_V3,
									},
								},
							},
						},
						AlpnProtocols: util.ALPNInMeshWithMxc,
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
		{
			name: "tls mode MUTUAL, CredentialName is set with proxy type Sidecar and destinationRule has workload Selector",
			opts: &buildClusterOpts{
				mutable:          newTestCluster(),
				isDrWithSelector: true,
			},
			tls: &networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_MUTUAL,
				CredentialName:  credentialName,
				SubjectAltNames: []string{"SAN"},
				Sni:             "some-sni.com",
			},
			result: expectedResult{
				tlsContext: &tls.UpstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						TlsParams: &tls.TlsParameters{
							// if not specified, envoy use TLSv1_2 as default for client.
							TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
							TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
						},
						TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
							{
								Name:      "kubernetes://" + credentialName,
								SdsConfig: authn_model.SDSAdsConfig,
							},
						},
						ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
							CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
								DefaultValidationContext: &tls.CertificateValidationContext{
									MatchSubjectAltNames: util.StringToExactMatch([]string{"SAN"}),
								},
								ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
									Name:      "kubernetes://" + credentialName + authn_model.SdsCaSuffix,
									SdsConfig: authn_model.SDSAdsConfig,
								},
							},
						},
					},
					Sni: "some-sni.com",
				},
				err: nil,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test.SetForTest(t, &features.EnableAutoSni, tc.enableAutoSni)
			test.SetForTest(t, &features.VerifyCertAtClient, tc.enableVerifyCertAtClient)
			var proxy *model.Proxy
			if tc.router {
				proxy = newGatewayProxy()
			} else {
				proxy = newSidecarProxy()
			}
			cb := NewClusterBuilder(proxy, nil, model.DisabledCache{})
			if tc.h2 {
				setH2Options(tc.opts.mutable)
			}
			ret, err := cb.buildUpstreamClusterTLSContext(tc.opts, tc.tls)
			if err != nil && tc.result.err == nil || err == nil && tc.result.err != nil {
				t.Errorf("expecting:\n err=%v but got err=%v", tc.result.err, err)
			} else if diff := cmp.Diff(tc.result.tlsContext, ret, protocmp.Transform()); diff != "" {
				t.Errorf("got diff: `%v", diff)
			}
			if tc.enableAutoSni {
				if len(tc.tls.Sni) == 0 {
					assert.Equal(t, tc.opts.mutable.httpProtocolOptions.UpstreamHttpProtocolOptions.AutoSni, true)
				}
				if tc.enableVerifyCertAtClient && len(tc.tls.SubjectAltNames) == 0 {
					assert.Equal(t, tc.opts.mutable.httpProtocolOptions.UpstreamHttpProtocolOptions.AutoSanValidation, true)
				}
			}
		})
	}
}

func newTestCluster() *clusterWrapper {
	return newClusterWrapper(&cluster.Cluster{
		Name: "test-cluster",
	})
}

func newH2TestCluster() *clusterWrapper {
	mc := newClusterWrapper(&cluster.Cluster{
		Name: "test-cluster",
	})
	setH2Options(mc)
	return mc
}

func newDownstreamTestCluster() *clusterWrapper {
	cb := NewClusterBuilder(newSidecarProxy(), nil, model.DisabledCache{})
	mc := newClusterWrapper(&cluster.Cluster{
		Name: "test-cluster",
	})
	cb.setUseDownstreamProtocol(mc)
	return mc
}

func newSidecarProxy() *model.Proxy {
	return &model.Proxy{Type: model.SidecarProxy, Metadata: &model.NodeMetadata{}}
}

func newGatewayProxy() *model.Proxy {
	return &model.Proxy{Type: model.Router, Metadata: &model.NodeMetadata{}}
}

// Helper function to extract TLS context from a cluster
func getTLSContext(t *testing.T, c *cluster.Cluster) *tls.UpstreamTlsContext {
	t.Helper()
	if c.TransportSocket == nil {
		return nil
	}
	tlsContext := &tls.UpstreamTlsContext{}
	err := c.TransportSocket.GetTypedConfig().UnmarshalTo(tlsContext)
	if err != nil {
		t.Fatalf("Failed to unmarshall tls context: %v", err)
	}
	return tlsContext
}

func TestShouldH2Upgrade(t *testing.T) {
	tests := []struct {
		name           string
		clusterName    string
		port           *model.Port
		mesh           *meshconfig.MeshConfig
		connectionPool *networking.ConnectionPoolSettings

		upgrade bool
	}{
		{
			name:        "mesh upgrade - dr default",
			clusterName: "bar",
			port:        &model.Port{Protocol: protocol.HTTP},
			mesh:        &meshconfig.MeshConfig{H2UpgradePolicy: meshconfig.MeshConfig_UPGRADE},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					H2UpgradePolicy: networking.ConnectionPoolSettings_HTTPSettings_DEFAULT,
				},
			},
			upgrade: true,
		},
		{
			name:        "mesh default - dr upgrade non http port",
			clusterName: "bar",
			port:        &model.Port{Protocol: protocol.Unsupported},
			mesh:        &meshconfig.MeshConfig{},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					H2UpgradePolicy: networking.ConnectionPoolSettings_HTTPSettings_UPGRADE,
				},
			},
			upgrade: true,
		},
		{
			name:        "mesh no_upgrade - dr default",
			clusterName: "bar",
			port:        &model.Port{Protocol: protocol.HTTP},
			mesh:        &meshconfig.MeshConfig{H2UpgradePolicy: meshconfig.MeshConfig_DO_NOT_UPGRADE},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					H2UpgradePolicy: networking.ConnectionPoolSettings_HTTPSettings_DEFAULT,
				},
			},
			upgrade: false,
		},
		{
			name:        "mesh no_upgrade - dr upgrade",
			clusterName: "bar",
			port:        &model.Port{Protocol: protocol.HTTP},
			mesh:        &meshconfig.MeshConfig{H2UpgradePolicy: meshconfig.MeshConfig_DO_NOT_UPGRADE},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					H2UpgradePolicy: networking.ConnectionPoolSettings_HTTPSettings_UPGRADE,
				},
			},
			upgrade: true,
		},
		{
			name:        "mesh upgrade - dr no_upgrade",
			clusterName: "bar",
			port:        &model.Port{Protocol: protocol.HTTP},
			mesh:        &meshconfig.MeshConfig{H2UpgradePolicy: meshconfig.MeshConfig_UPGRADE},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					H2UpgradePolicy: networking.ConnectionPoolSettings_HTTPSettings_DO_NOT_UPGRADE,
				},
			},
			upgrade: false,
		},
		{
			name:        "non-http",
			clusterName: "bar",
			port:        &model.Port{Protocol: protocol.Unsupported},
			mesh:        &meshconfig.MeshConfig{H2UpgradePolicy: meshconfig.MeshConfig_UPGRADE},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					H2UpgradePolicy: networking.ConnectionPoolSettings_HTTPSettings_DEFAULT,
				},
			},
			upgrade: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			upgrade := shouldH2Upgrade(test.clusterName, test.port, test.mesh, test.connectionPool)

			if upgrade != test.upgrade {
				t.Fatalf("got: %t, want: %t (%v, %v)", upgrade, test.upgrade, test.mesh.H2UpgradePolicy, test.connectionPool.Http.H2UpgradePolicy)
			}
		})
	}
}

// nolint
func TestIsHttp2Cluster(t *testing.T) {
	tests := []struct {
		name           string
		cluster        *clusterWrapper
		isHttp2Cluster bool // revive:disable-line
	}{
		{
			name:           "with no h2 options",
			cluster:        newTestCluster(),
			isHttp2Cluster: false,
		},
		{
			name:           "with h2 options",
			cluster:        newH2TestCluster(),
			isHttp2Cluster: true,
		},
		{
			name:           "with downstream config and h2 options",
			cluster:        newDownstreamTestCluster(),
			isHttp2Cluster: false,
		},
	}

	cb := NewClusterBuilder(newSidecarProxy(), nil, model.DisabledCache{})

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isHttp2Cluster := cb.isHttp2Cluster(test.cluster) // revive:disable-line
			if isHttp2Cluster != test.isHttp2Cluster {
				t.Errorf("got: %t, want: %t", isHttp2Cluster, test.isHttp2Cluster)
			}
		})
	}
}

func TestBuildAutoMtlsSettings(t *testing.T) {
	tlsSettings := &networking.ClientTLSSettings{
		Mode:            networking.ClientTLSSettings_ISTIO_MUTUAL,
		SubjectAltNames: []string{"custom.foo.com"},
		Sni:             "custom.foo.com",
	}
	tests := []struct {
		name            string
		tls             *networking.ClientTLSSettings
		sans            []string
		sni             string
		proxy           *model.Proxy
		autoMTLSEnabled bool
		meshExternal    bool
		serviceMTLSMode model.MutualTLSMode
		want            *networking.ClientTLSSettings
		wantCtxType     mtlsContextType
	}{
		{
			"Destination rule TLS sni and SAN override",
			tlsSettings,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{}},
			false, false, model.MTLSUnknown,
			tlsSettings,
			userSupplied,
		},
		{
			"Metadata cert path override ISTIO_MUTUAL",
			tlsSettings,
			[]string{"custom.foo.com"},
			"custom.foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{
				TLSClientCertChain: "/custom/chain.pem",
				TLSClientKey:       "/custom/key.pem",
				TLSClientRootCert:  "/custom/root.pem",
			}},
			false, false, model.MTLSUnknown,
			&networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_MUTUAL,
				PrivateKey:        "/custom/key.pem",
				ClientCertificate: "/custom/chain.pem",
				CaCertificates:    "/custom/root.pem",
				SubjectAltNames:   []string{"custom.foo.com"},
				Sni:               "custom.foo.com",
			},
			userSupplied,
		},
		{
			"Auto fill nil settings when mTLS nil for internal service in strict mode",
			nil,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{}},
			true, false, model.MTLSStrict,
			&networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_ISTIO_MUTUAL,
				SubjectAltNames: []string{"spiffe://foo/serviceaccount/1"},
				Sni:             "foo.com",
			},
			autoDetected,
		},
		{
			"Auto fill nil settings when mTLS nil for internal service in permissive mode",
			nil,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{}},
			true, false, model.MTLSPermissive,
			&networking.ClientTLSSettings{
				Mode:            networking.ClientTLSSettings_ISTIO_MUTUAL,
				SubjectAltNames: []string{"spiffe://foo/serviceaccount/1"},
				Sni:             "foo.com",
			},
			autoDetected,
		},
		{
			"Auto fill nil settings when mTLS nil for internal service in plaintext mode",
			nil,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{}},
			true, false, model.MTLSDisable,
			nil,
			userSupplied,
		},
		{
			"Auto fill nil settings when mTLS nil for internal service in unknown mode",
			nil,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{}},
			true, false, model.MTLSUnknown,
			nil,
			userSupplied,
		},
		{
			"Do not auto fill nil settings for external",
			nil,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{}},
			true, true, model.MTLSUnknown,
			nil,
			userSupplied,
		},
		{
			"Do not auto fill nil settings if server mTLS is disabled",
			nil,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{}},
			false, false, model.MTLSDisable,
			nil,
			userSupplied,
		},
		{
			"TLS nil auto build tls with metadata cert path",
			nil,
			[]string{"spiffe://foo/serviceaccount/1"},
			"foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{
				TLSClientCertChain: "/custom/chain.pem",
				TLSClientKey:       "/custom/key.pem",
				TLSClientRootCert:  "/custom/root.pem",
			}},
			true, false, model.MTLSPermissive,
			&networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_MUTUAL,
				ClientCertificate: "/custom/chain.pem",
				PrivateKey:        "/custom/key.pem",
				CaCertificates:    "/custom/root.pem",
				SubjectAltNames:   []string{"spiffe://foo/serviceaccount/1"},
				Sni:               "foo.com",
			},
			autoDetected,
		},
		{
			"Simple TLS",
			&networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_SIMPLE,
				PrivateKey:        "/custom/key.pem",
				ClientCertificate: "/custom/chain.pem",
				CaCertificates:    "/custom/root.pem",
			},
			[]string{"custom.foo.com"},
			"custom.foo.com",
			&model.Proxy{Metadata: &model.NodeMetadata{
				TLSClientCertChain: "/custom/meta/chain.pem",
				TLSClientKey:       "/custom/meta/key.pem",
				TLSClientRootCert:  "/custom/meta/root.pem",
			}},
			false, false, model.MTLSUnknown,
			&networking.ClientTLSSettings{
				Mode:              networking.ClientTLSSettings_SIMPLE,
				PrivateKey:        "/custom/key.pem",
				ClientCertificate: "/custom/chain.pem",
				CaCertificates:    "/custom/root.pem",
			},
			userSupplied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := NewClusterBuilder(tt.proxy, nil, nil)
			gotTLS, gotCtxType := cb.buildUpstreamTlsSettings(tt.tls, tt.sans, tt.sni, tt.autoMTLSEnabled, tt.meshExternal, tt.serviceMTLSMode)
			if !reflect.DeepEqual(gotTLS, tt.want) {
				t.Errorf("cluster TLS does not match expected result want %#v, got %#v", tt.want, gotTLS)
			}
			if gotCtxType != tt.wantCtxType {
				t.Errorf("cluster TLS context type does not match expected result want %#v, got %#v", tt.wantCtxType, gotCtxType)
			}
		})
	}
}

func TestApplyDestinationRuleOSCACert(t *testing.T) {
	servicePort := model.PortList{
		&model.Port{
			Name:     "default",
			Port:     8080,
			Protocol: protocol.HTTP,
		},
		&model.Port{
			Name:     "auto",
			Port:     9090,
			Protocol: protocol.Unsupported,
		},
	}
	service := &model.Service{
		Hostname:   host.Name("foo.default.svc.cluster.local"),
		Ports:      servicePort,
		Resolution: model.ClientSideLB,
		Attributes: model.ServiceAttributes{
			Namespace: TestServiceNamespace,
		},
	}

	cases := []struct {
		name                      string
		cluster                   *cluster.Cluster
		clusterMode               ClusterMode
		service                   *model.Service
		port                      *model.Port
		proxyView                 model.ProxyView
		destRule                  *networking.DestinationRule
		expectedCaCertificateName string
		enableVerifyCertAtClient  bool
	}{
		{
			name:        "VerifyCertAtClient set and destination rule with empty string CaCertificates",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					ConnectionPool: &networking.ConnectionPoolSettings{
						Http: &networking.ConnectionPoolSettings_HTTPSettings{
							MaxRetries:        10,
							UseClientProtocol: true,
						},
					},
					Tls: &networking.ClientTLSSettings{
						CaCertificates: "",
						Mode:           networking.ClientTLSSettings_SIMPLE,
					},
				},
			},
			expectedCaCertificateName: "system",
			enableVerifyCertAtClient:  true,
		},
		{
			name:        "VerifyCertAtClient set and destination rule with CaCertificates",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					ConnectionPool: &networking.ConnectionPoolSettings{
						Http: &networking.ConnectionPoolSettings_HTTPSettings{
							MaxRetries:        10,
							UseClientProtocol: true,
						},
					},
					Tls: &networking.ClientTLSSettings{
						CaCertificates: constants.DefaultRootCert,
						Mode:           networking.ClientTLSSettings_SIMPLE,
					},
				},
			},
			expectedCaCertificateName: constants.DefaultRootCert,
			enableVerifyCertAtClient:  true,
		},
		{
			name:        "VerifyCertAtClient set and destination rule without CaCertificates",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					ConnectionPool: &networking.ConnectionPoolSettings{
						Http: &networking.ConnectionPoolSettings_HTTPSettings{
							MaxRetries:        10,
							UseClientProtocol: true,
						},
					},
					Tls: &networking.ClientTLSSettings{
						Mode: networking.ClientTLSSettings_SIMPLE,
					},
				},
			},
			expectedCaCertificateName: "system",
			enableVerifyCertAtClient:  true,
		},
		{
			name:        "VerifyCertAtClient false and destination rule without CaCertificates",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					ConnectionPool: &networking.ConnectionPoolSettings{
						Http: &networking.ConnectionPoolSettings_HTTPSettings{
							MaxRetries:        10,
							UseClientProtocol: true,
						},
					},
					Tls: &networking.ClientTLSSettings{
						Mode: networking.ClientTLSSettings_SIMPLE,
					},
				},
			},
			expectedCaCertificateName: "",
			enableVerifyCertAtClient:  false,
		},
		{
			name:        "VerifyCertAtClient false and destination rule with CaCertificates",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					ConnectionPool: &networking.ConnectionPoolSettings{
						Http: &networking.ConnectionPoolSettings_HTTPSettings{
							MaxRetries:        10,
							UseClientProtocol: true,
						},
					},
					Tls: &networking.ClientTLSSettings{
						CaCertificates: constants.DefaultRootCert,
						Mode:           networking.ClientTLSSettings_SIMPLE,
					},
				},
			},
			expectedCaCertificateName: constants.DefaultRootCert,
			enableVerifyCertAtClient:  false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			test.SetForTest(t, &features.VerifyCertAtClient, tt.enableVerifyCertAtClient)
			instances := []*model.ServiceInstance{
				{
					Service:     tt.service,
					ServicePort: tt.port,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.1",
						EndpointPort: 10001,
						Locality: model.Locality{
							ClusterID: "",
							Label:     "region1/zone1/subzone1",
						},
						TLSMode: model.IstioMutualTLSModeLabel,
					},
				},
			}

			var cfg *config.Config
			if tt.destRule != nil {
				cfg = &config.Config{
					Meta: config.Meta{
						GroupVersionKind: gvk.DestinationRule,
						Name:             "acme",
						Namespace:        "default",
					},
					Spec: tt.destRule,
				}
			}
			cg := NewConfigGenTest(t, TestOptions{
				ConfigPointers: []*config.Config{cfg},
				Services:       []*model.Service{tt.service},
			})
			cg.MemRegistry.WantGetProxyServiceInstances = instances
			proxy := cg.SetupProxy(nil)
			cb := NewClusterBuilder(proxy, &model.PushRequest{Push: cg.PushContext()}, nil)

			tt.cluster.CommonLbConfig = &cluster.Cluster_CommonLbConfig{}

			ec := newClusterWrapper(tt.cluster)
			destRule := proxy.SidecarScope.DestinationRule(model.TrafficDirectionOutbound, proxy, tt.service.Hostname).GetRule()

			// ACT
			_ = cb.applyDestinationRule(ec, tt.clusterMode, tt.service, tt.port, tt.proxyView, destRule, nil)

			byteArray, err := config.ToJSON(destRule.Spec)
			if err != nil {
				t.Errorf("Could not parse destination rule: %v", err)
			}
			dr := &networking.DestinationRule{}
			err = json.Unmarshal(byteArray, dr)
			if err != nil {
				t.Errorf("Could not unmarshal destination rule: %v", err)
			}
			ca := dr.TrafficPolicy.Tls.CaCertificates
			if ca != tt.expectedCaCertificateName {
				t.Errorf("%v: got unexpected caCertitifcates field. Expected (%v), received (%v)", tt.name, tt.expectedCaCertificateName, ca)
			}
		})
	}
}

func TestApplyTCPKeepalive(t *testing.T) {
	cases := []struct {
		name           string
		mesh           *meshconfig.MeshConfig
		connectionPool *networking.ConnectionPoolSettings
		wantConnOpts   *cluster.UpstreamConnectionOptions
	}{
		{
			name:           "no tcp alive",
			mesh:           &meshconfig.MeshConfig{},
			connectionPool: &networking.ConnectionPoolSettings{},
			wantConnOpts:   nil,
		},
		{
			name: "destination rule tcp alive",
			mesh: &meshconfig.MeshConfig{},
			connectionPool: &networking.ConnectionPoolSettings{
				Tcp: &networking.ConnectionPoolSettings_TCPSettings{
					TcpKeepalive: &networking.ConnectionPoolSettings_TCPSettings_TcpKeepalive{
						Time: &durationpb.Duration{Seconds: 10},
					},
				},
			},
			wantConnOpts: &cluster.UpstreamConnectionOptions{
				TcpKeepalive: &core.TcpKeepalive{
					KeepaliveTime: &wrappers.UInt32Value{Value: uint32(10)},
				},
			},
		},
		{
			name: "mesh tcp alive",
			mesh: &meshconfig.MeshConfig{
				TcpKeepalive: &networking.ConnectionPoolSettings_TCPSettings_TcpKeepalive{
					Time: &durationpb.Duration{Seconds: 10},
				},
			},
			connectionPool: &networking.ConnectionPoolSettings{},
			wantConnOpts: &cluster.UpstreamConnectionOptions{
				TcpKeepalive: &core.TcpKeepalive{
					KeepaliveTime: &wrappers.UInt32Value{Value: uint32(10)},
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cg := NewConfigGenTest(t, TestOptions{})
			proxy := cg.SetupProxy(nil)
			cb := NewClusterBuilder(proxy, &model.PushRequest{Push: cg.PushContext()}, nil)
			mc := &clusterWrapper{
				cluster: &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			}

			cb.applyConnectionPool(tt.mesh, mc, tt.connectionPool)

			if !reflect.DeepEqual(tt.wantConnOpts, mc.cluster.UpstreamConnectionOptions) {
				t.Errorf("unexpected tcp keepalive settings, want %v, got %v", tt.wantConnOpts,
					mc.cluster.UpstreamConnectionOptions)
			}
		})
	}
}

func TestApplyConnectionPool(t *testing.T) {
	cases := []struct {
		name                string
		cluster             *cluster.Cluster
		httpProtocolOptions *http.HttpProtocolOptions
		connectionPool      *networking.ConnectionPoolSettings
		expectedHTTPPOpt    *http.HttpProtocolOptions
	}{
		{
			name:    "only update IdleTimeout",
			cluster: &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			httpProtocolOptions: &http.HttpProtocolOptions{
				CommonHttpProtocolOptions: &core.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{
						Seconds: 10,
					},
					MaxRequestsPerConnection: &wrappers.UInt32Value{Value: 10},
				},
			},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					IdleTimeout: &durationpb.Duration{
						Seconds: 22,
					},
				},
			},
			expectedHTTPPOpt: &http.HttpProtocolOptions{
				CommonHttpProtocolOptions: &core.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{
						Seconds: 22,
					},
					MaxRequestsPerConnection: &wrappers.UInt32Value{Value: 10},
				},
			},
		},
		{
			name:    "only update MaxRequestsPerConnection ",
			cluster: &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			httpProtocolOptions: &http.HttpProtocolOptions{
				CommonHttpProtocolOptions: &core.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{
						Seconds: 10,
					},
					MaxRequestsPerConnection: &wrappers.UInt32Value{Value: 10},
				},
			},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					MaxRequestsPerConnection: 22,
				},
			},
			expectedHTTPPOpt: &http.HttpProtocolOptions{
				CommonHttpProtocolOptions: &core.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{
						Seconds: 10,
					},
					MaxRequestsPerConnection: &wrappers.UInt32Value{Value: 22},
				},
			},
		},
		{
			name:    "update multiple fields",
			cluster: &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			httpProtocolOptions: &http.HttpProtocolOptions{
				CommonHttpProtocolOptions: &core.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{
						Seconds: 10,
					},
					MaxRequestsPerConnection: &wrappers.UInt32Value{Value: 10},
				},
			},
			connectionPool: &networking.ConnectionPoolSettings{
				Http: &networking.ConnectionPoolSettings_HTTPSettings{
					IdleTimeout: &durationpb.Duration{
						Seconds: 22,
					},
					MaxRequestsPerConnection: 22,
				},
				Tcp: &networking.ConnectionPoolSettings_TCPSettings{
					MaxConnectionDuration: &durationpb.Duration{
						Seconds: 500,
					},
				},
			},
			expectedHTTPPOpt: &http.HttpProtocolOptions{
				CommonHttpProtocolOptions: &core.HttpProtocolOptions{
					IdleTimeout: &durationpb.Duration{
						Seconds: 22,
					},
					MaxRequestsPerConnection: &wrappers.UInt32Value{Value: 22},
					MaxConnectionDuration: &durationpb.Duration{
						Seconds: 500,
					},
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cg := NewConfigGenTest(t, TestOptions{})
			proxy := cg.SetupProxy(nil)
			cb := NewClusterBuilder(proxy, &model.PushRequest{Push: cg.PushContext()}, nil)
			mc := &clusterWrapper{
				cluster:             tt.cluster,
				httpProtocolOptions: tt.httpProtocolOptions,
			}

			opts := buildClusterOpts{
				mesh:    cb.req.Push.Mesh,
				mutable: mc,
			}
			cb.applyConnectionPool(opts.mesh, opts.mutable, tt.connectionPool)
			// assert httpProtocolOptions
			assert.Equal(t, opts.mutable.httpProtocolOptions.CommonHttpProtocolOptions.IdleTimeout,
				tt.expectedHTTPPOpt.CommonHttpProtocolOptions.IdleTimeout)
			assert.Equal(t, opts.mutable.httpProtocolOptions.CommonHttpProtocolOptions.MaxRequestsPerConnection,
				tt.expectedHTTPPOpt.CommonHttpProtocolOptions.MaxRequestsPerConnection)
			assert.Equal(t, opts.mutable.httpProtocolOptions.CommonHttpProtocolOptions.MaxConnectionDuration,
				tt.expectedHTTPPOpt.CommonHttpProtocolOptions.MaxConnectionDuration)
		})
	}
}

func TestBuildExternalSDSClusters(t *testing.T) {
	proxy := &model.Proxy{
		Metadata: &model.NodeMetadata{
			Raw: map[string]any{
				security.CredentialMetaDataName: "true",
			},
		},
	}

	cases := []struct {
		name         string
		expectedName string
		expectedPath string
	}{
		{
			name:         "uds",
			expectedName: security.SDSExternalClusterName,
			expectedPath: security.CredentialNameSocketPath,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			cg := NewConfigGenTest(t, TestOptions{})
			cb := NewClusterBuilder(cg.SetupProxy(proxy), &model.PushRequest{Push: cg.PushContext()}, nil)
			cluster := cb.buildExternalSDSCluster(security.CredentialNameSocketPath)
			path := cluster.LoadAssignment.Endpoints[0].LbEndpoints[0].GetEndpoint().Address.GetPipe().Path
			anyOptions := cluster.TypedExtensionProtocolOptions[v3.HttpProtocolOptionsType]
			if anyOptions == nil {
				t.Errorf("cluster has no httpProtocolOptions")
			}
			if cluster.Name != tt.expectedName {
				t.Errorf("Unexpected cluster name, got: %v, want: %v", cluster.Name, tt.expectedName)
			}
			if path != tt.expectedPath {
				t.Errorf("Unexpected path, got: %v, want: %v", path, tt.expectedPath)
			}
		})
	}
}

func TestInsecureSkipVerify(t *testing.T) {
	servicePort := model.PortList{
		&model.Port{
			Name:     "default",
			Port:     8080,
			Protocol: protocol.HTTP,
		},
		&model.Port{
			Name:     "auto",
			Port:     9090,
			Protocol: protocol.Unsupported,
		},
	}

	service := &model.Service{
		Hostname:   host.Name("foo.default.svc.cluster.local"),
		Ports:      servicePort,
		Resolution: model.ClientSideLB,
		Attributes: model.ServiceAttributes{
			Namespace:       TestServiceNamespace,
			ServiceRegistry: provider.External,
		},
	}

	cases := []struct {
		name                     string
		cluster                  *cluster.Cluster
		clusterMode              ClusterMode
		service                  *model.Service
		port                     *model.Port
		proxyView                model.ProxyView
		destRule                 *networking.DestinationRule
		serviceAcct              []string // SE SAN values
		enableAutoSni            bool
		enableVerifyCertAtClient bool
		expectTLSContext         *tls.UpstreamTlsContext
	}{
		{
			name:        "With tls mode simple, InsecureSkipVerify is not specified and ca cert is supplied",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:            networking.ClientTLSSettings_SIMPLE,
						CaCertificates:  constants.RootCertFilename,
						Sni:             "foo.default.svc.cluster.local",
						SubjectAltNames: []string{"foo.default.svc.cluster.local"},
					},
				},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: false,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
						CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
							DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"foo.default.svc.cluster.local"})},
							ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
								Name: "file-root:" + constants.RootCertFilename,
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									ResourceApiVersion: core.ApiVersion_V3,
								},
							},
						},
					},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode simple, InsecureSkipVerify is set false and ca cert is supplied",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_SIMPLE,
						CaCertificates:     constants.RootCertFilename,
						Sni:                "foo.default.svc.cluster.local",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: false},
					},
				},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: false,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
						CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
							DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"foo.default.svc.cluster.local"})},
							ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
								Name: "file-root:" + constants.RootCertFilename,
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									ResourceApiVersion: core.ApiVersion_V3,
								},
							},
						},
					},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode simple, InsecureSkipVerify is set true and env VERIFY_CERTIFICATE_AT_CLIENT is true",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_SIMPLE,
						Sni:                "foo.default.svc.cluster.local",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: true},
					},
				},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: true,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode simple, InsecureSkipVerify is set true and env VERIFY_CERTIFICATE_AT_CLIENT is true and AUTO_SNI is true",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_SIMPLE,
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: true},
					},
				},
			},
			enableAutoSni:            true,
			enableVerifyCertAtClient: true,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
				},
			},
		},
		{
			name:        "With tls mode simple and CredentialName, InsecureSkipVerify is set true and env VERIFY_CERTIFICATE_AT_CLIENT is true",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_SIMPLE,
						CredentialName:     "ca-cert",
						Sni:                "foo.default.svc.cluster.local",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: true},
					},
				},
				WorkloadSelector: &v1beta1.WorkloadSelector{},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: true,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode mutual, InsecureSkipVerify is not specified and ca cert is supplied",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:              networking.ClientTLSSettings_MUTUAL,
						ClientCertificate: "cert",
						PrivateKey:        "key",
						CaCertificates:    constants.RootCertFilename,
						Sni:               "foo.default.svc.cluster.local",
						SubjectAltNames:   []string{"foo.default.svc.cluster.local"},
					},
				},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: false,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
						{
							Name: "file-cert:cert~key",
							SdsConfig: &core.ConfigSource{
								ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
									ApiConfigSource: &core.ApiConfigSource{
										ApiType:                   core.ApiConfigSource_GRPC,
										SetNodeOnFirstMessageOnly: true,
										TransportApiVersion:       core.ApiVersion_V3,
										GrpcServices: []*core.GrpcService{
											{
												TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
												},
											},
										},
									},
								},
								ResourceApiVersion: core.ApiVersion_V3,
							},
						},
					},
					ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
						CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
							DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"foo.default.svc.cluster.local"})},
							ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
								Name: "file-root:" + constants.RootCertFilename,
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									ResourceApiVersion: core.ApiVersion_V3,
								},
							},
						},
					},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode mutual, InsecureSkipVerify is set false and ca cert is supplied",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_MUTUAL,
						ClientCertificate:  "cert",
						PrivateKey:         "key",
						CaCertificates:     constants.RootCertFilename,
						Sni:                "foo.default.svc.cluster.local",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: false},
					},
				},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: false,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
						{
							Name: "file-cert:cert~key",
							SdsConfig: &core.ConfigSource{
								ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
									ApiConfigSource: &core.ApiConfigSource{
										ApiType:                   core.ApiConfigSource_GRPC,
										SetNodeOnFirstMessageOnly: true,
										TransportApiVersion:       core.ApiVersion_V3,
										GrpcServices: []*core.GrpcService{
											{
												TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
												},
											},
										},
									},
								},
								ResourceApiVersion: core.ApiVersion_V3,
							},
						},
					},
					ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
						CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
							DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"foo.default.svc.cluster.local"})},
							ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
								Name: "file-root:" + constants.RootCertFilename,
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									ResourceApiVersion: core.ApiVersion_V3,
								},
							},
						},
					},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode mutual, InsecureSkipVerify is set true and env VERIFY_CERTIFICATE_AT_CLIENT is true",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_MUTUAL,
						ClientCertificate:  "cert",
						PrivateKey:         "key",
						Sni:                "foo.default.svc.cluster.local",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: true},
					},
				},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: true,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
						{
							Name: "file-cert:cert~key",
							SdsConfig: &core.ConfigSource{
								ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
									ApiConfigSource: &core.ApiConfigSource{
										ApiType:                   core.ApiConfigSource_GRPC,
										SetNodeOnFirstMessageOnly: true,
										TransportApiVersion:       core.ApiVersion_V3,
										GrpcServices: []*core.GrpcService{
											{
												TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
												},
											},
										},
									},
								},
								ResourceApiVersion: core.ApiVersion_V3,
							},
						},
					},
					ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode mutual, InsecureSkipVerify is set true and env VERIFY_CERTIFICATE_AT_CLIENT is true and AUTO_SNI is true",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_MUTUAL,
						ClientCertificate:  "cert",
						PrivateKey:         "key",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: true},
					},
				},
			},
			enableAutoSni:            true,
			enableVerifyCertAtClient: true,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
						{
							Name: "file-cert:cert~key",
							SdsConfig: &core.ConfigSource{
								ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
									ApiConfigSource: &core.ApiConfigSource{
										ApiType:                   core.ApiConfigSource_GRPC,
										SetNodeOnFirstMessageOnly: true,
										TransportApiVersion:       core.ApiVersion_V3,
										GrpcServices: []*core.GrpcService{
											{
												TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
												},
											},
										},
									},
								},
								ResourceApiVersion: core.ApiVersion_V3,
							},
						},
					},
					ValidationContextType: &tls.CommonTlsContext_ValidationContext{},
				},
			},
		},
		{
			name:        "With tls mode mutual and CredentialName, InsecureSkipVerify is set true and env VERIFY_CERTIFICATE_AT_CLIENT is true",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_MUTUAL,
						CredentialName:     "server-cert",
						Sni:                "foo.default.svc.cluster.local",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: true},
					},
				},
				WorkloadSelector: &v1beta1.WorkloadSelector{},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: true,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
						{
							Name: "kubernetes://server-cert",
							SdsConfig: &core.ConfigSource{
								ConfigSourceSpecifier: &core.ConfigSource_Ads{
									Ads: &core.AggregatedConfigSource{},
								},
								ResourceApiVersion: core.ApiVersion_V3,
							},
						},
					},
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
		{
			name:        "With tls mode istio mutual, InsecureSkipVerify is set true",
			cluster:     &cluster.Cluster{Name: "foo", ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS}},
			clusterMode: DefaultClusterMode,
			service:     service,
			port:        servicePort[0],
			proxyView:   model.ProxyViewAll,
			destRule: &networking.DestinationRule{
				Host: "foo.default.svc.cluster.local",
				TrafficPolicy: &networking.TrafficPolicy{
					Tls: &networking.ClientTLSSettings{
						Mode:               networking.ClientTLSSettings_ISTIO_MUTUAL,
						Sni:                "foo.default.svc.cluster.local",
						SubjectAltNames:    []string{"foo.default.svc.cluster.local"},
						InsecureSkipVerify: &wrappers.BoolValue{Value: true},
					},
				},
			},
			enableAutoSni:            false,
			enableVerifyCertAtClient: true,
			expectTLSContext: &tls.UpstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsParams: &tls.TlsParameters{
						// if not specified, envoy use TLSv1_2 as default for client.
						TlsMaximumProtocolVersion: tls.TlsParameters_TLSv1_3,
						TlsMinimumProtocolVersion: tls.TlsParameters_TLSv1_2,
					},
					TlsCertificateSdsSecretConfigs: []*tls.SdsSecretConfig{
						{
							Name: authn_model.SDSDefaultResourceName,
							SdsConfig: &core.ConfigSource{
								ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
									ApiConfigSource: &core.ApiConfigSource{
										ApiType:                   core.ApiConfigSource_GRPC,
										SetNodeOnFirstMessageOnly: true,
										TransportApiVersion:       core.ApiVersion_V3,
										GrpcServices: []*core.GrpcService{
											{
												TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
													EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
												},
											},
										},
									},
								},
								ResourceApiVersion:  core.ApiVersion_V3,
								InitialFetchTimeout: durationpb.New(time.Second * 0),
							},
						},
					},
					ValidationContextType: &tls.CommonTlsContext_CombinedValidationContext{
						CombinedValidationContext: &tls.CommonTlsContext_CombinedCertificateValidationContext{
							DefaultValidationContext: &tls.CertificateValidationContext{MatchSubjectAltNames: util.StringToExactMatch([]string{"foo.default.svc.cluster.local"})},
							ValidationContextSdsSecretConfig: &tls.SdsSecretConfig{
								Name: authn_model.SDSRootResourceName,
								SdsConfig: &core.ConfigSource{
									ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
										ApiConfigSource: &core.ApiConfigSource{
											ApiType:                   core.ApiConfigSource_GRPC,
											SetNodeOnFirstMessageOnly: true,
											TransportApiVersion:       core.ApiVersion_V3,
											GrpcServices: []*core.GrpcService{
												{
													TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
														EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds-grpc"},
													},
												},
											},
										},
									},
									ResourceApiVersion:  core.ApiVersion_V3,
									InitialFetchTimeout: durationpb.New(time.Second * 0),
								},
							},
						},
					},
					AlpnProtocols: util.ALPNInMeshWithMxc,
				},
				Sni: "foo.default.svc.cluster.local",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			test.SetForTest(t, &features.EnableAutoSni, tc.enableAutoSni)
			test.SetForTest(t, &features.VerifyCertAtClient, tc.enableVerifyCertAtClient)

			instances := []*model.ServiceInstance{
				{
					Service:     tc.service,
					ServicePort: tc.port,
					Endpoint: &model.IstioEndpoint{
						Address:      "192.168.1.1",
						EndpointPort: 10001,
						Locality: model.Locality{
							ClusterID: "",
							Label:     "region1/zone1/subzone1",
						},
						TLSMode: model.IstioMutualTLSModeLabel,
					},
				},
			}

			var cfg *config.Config
			if tc.destRule != nil {
				cfg = &config.Config{
					Meta: config.Meta{
						GroupVersionKind: gvk.DestinationRule,
						Name:             "acme",
						Namespace:        "default",
					},
					Spec: tc.destRule,
				}
			}

			cg := NewConfigGenTest(t, TestOptions{
				ConfigPointers: []*config.Config{cfg},
				Services:       []*model.Service{tc.service},
			})

			cg.MemRegistry.WantGetProxyServiceInstances = instances
			proxy := cg.SetupProxy(nil)
			cb := NewClusterBuilder(proxy, &model.PushRequest{Push: cg.PushContext()}, nil)
			ec := newClusterWrapper(tc.cluster)
			tc.cluster.CommonLbConfig = &cluster.Cluster_CommonLbConfig{}
			destRule := proxy.SidecarScope.DestinationRule(model.TrafficDirectionOutbound, proxy, tc.service.Hostname).GetRule()
			_ = cb.applyDestinationRule(ec, tc.clusterMode, tc.service, tc.port, tc.proxyView, destRule, tc.serviceAcct)

			result := getTLSContext(t, ec.cluster)
			if diff := cmp.Diff(result, tc.expectTLSContext, protocmp.Transform()); diff != "" {
				t.Errorf("got diff: `%v", diff)
			}

			if tc.enableAutoSni {
				if tc.destRule.GetTrafficPolicy().GetTls().Sni == "" {
					assert.Equal(t, ec.httpProtocolOptions.UpstreamHttpProtocolOptions.AutoSni, true)
				}

				if tc.destRule.GetTrafficPolicy().GetTls().GetInsecureSkipVerify().GetValue() {
					assert.Equal(t, ec.httpProtocolOptions.UpstreamHttpProtocolOptions.AutoSanValidation, false)
				} else if tc.enableVerifyCertAtClient && len(tc.destRule.GetTrafficPolicy().GetTls().SubjectAltNames) == 0 {
					assert.Equal(t, ec.httpProtocolOptions.UpstreamHttpProtocolOptions.AutoSanValidation, true)
				}
			}
		})
	}
}

func TestConfigureALPNOverride(t *testing.T) {
	cases := []struct {
		name     string
		tlsMode  networking.ClientTLSSettings_TLSmode
		metadata *core.Metadata
		want     *core.Metadata
	}{
		{
			name:     "tlsMode SIMPLE, metadata nil",
			tlsMode:  networking.ClientTLSSettings_SIMPLE,
			metadata: nil,
			want: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					util.IstioMetadataKey: {
						Fields: map[string]*structpb.Value{
							util.AlpnOverrideMetadataKey: {
								Kind: &structpb.Value_StringValue{
									StringValue: "false",
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "tlsMode MUTUAL, metadata not nil",
			tlsMode: networking.ClientTLSSettings_MUTUAL,
			metadata: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					util.IstioMetadataKey: {
						Fields: map[string]*structpb.Value{
							"other-config": {
								Kind: &structpb.Value_StringValue{
									StringValue: "other-config",
								},
							},
						},
					},
				},
			},
			want: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					util.IstioMetadataKey: {
						Fields: map[string]*structpb.Value{
							"other-config": {
								Kind: &structpb.Value_StringValue{
									StringValue: "other-config",
								},
							},
							util.AlpnOverrideMetadataKey: {
								Kind: &structpb.Value_StringValue{
									StringValue: "false",
								},
							},
						},
					},
				},
			},
		},
		{
			name:     "tlsMode ISTIO_MUTUAL, metadata nil",
			tlsMode:  networking.ClientTLSSettings_ISTIO_MUTUAL,
			metadata: nil,
			want:     nil,
		},
		{
			name:    "tlsMode ISTIO_MUTUAL, metadata not nil",
			tlsMode: networking.ClientTLSSettings_ISTIO_MUTUAL,
			metadata: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					util.IstioMetadataKey: {
						Fields: map[string]*structpb.Value{
							"other-config": {
								Kind: &structpb.Value_StringValue{
									StringValue: "other-config",
								},
							},
						},
					},
				},
			},
			want: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					util.IstioMetadataKey: {
						Fields: map[string]*structpb.Value{
							"other-config": {
								Kind: &structpb.Value_StringValue{
									StringValue: "other-config",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			newMetadata := configureALPNOverride(tt.tlsMode, tt.metadata)
			if diff := cmp.Diff(newMetadata, tt.want, protocmp.Transform()); diff != "" {
				t.Errorf("configureALPNOverride(%s, %v) produced incorrect result:\ngot: %v\nwant: %v\nDiff: %s", tt.tlsMode, tt.metadata, newMetadata, tt.want, diff)
			}
		})
	}
}
