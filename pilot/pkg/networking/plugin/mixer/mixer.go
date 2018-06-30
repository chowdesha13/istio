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

package mixer

import (
	"fmt"
	"net"
	"strings"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	"github.com/gogo/protobuf/types"

	meshconfig "istio.io/api/mesh/v1alpha1"
	mpb "istio.io/api/mixer/v1"
	mccpb "istio.io/api/mixer/v1/config/client"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/log"
)

type mixerplugin struct{}

type attribute = *mpb.Attributes_AttributeValue

type attributes map[string]attribute

const (
	//mixerPortName       = "grpc-mixer"
	// defined in install/kubernetes/helm/istio/charts/mixer/templates/service.yaml
	mixerPortNumber = 9091

	//mixerMTLSPortName   = "grpc-mixer-mtls"
	mixerMTLSPortNumber = 15004

	// mixer filter name
	mixer = "mixer"
)

// NewPlugin returns an ptr to an initialized mixer.Plugin.
func NewPlugin() plugin.Plugin {
	return mixerplugin{}
}

// OnOutboundListener implements the Callbacks interface method.
func (mixerplugin) OnOutboundListener(in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	if in.Env.Mesh.MixerCheckServer == "" && in.Env.Mesh.MixerReportServer == "" {
		return nil
	}

	attrs := attributes{
		"source.uid":            attrUID(in.Node),
		"source.namespace":      attrNamespace(in.Node),
		"context.reporter.uid":  attrUID(in.Node),
		"context.reporter.type": attrStringValue("outbound"),
	}

	switch in.ListenerProtocol {
	case plugin.ListenerProtocolHTTP:
		filter := buildOutboundHTTPFilter(in.Env.Mesh, attrs, in.Node)
		for cnum := range mutable.FilterChains {
			mutable.FilterChains[cnum].HTTP = append(mutable.FilterChains[cnum].HTTP, filter)
		}
		return nil
	case plugin.ListenerProtocolTCP:
		filter := buildOutboundTCPFilter(in.Env.Mesh, attrs, in.Node, in.Service, in.Env.ServiceDiscovery)
		for cnum := range mutable.FilterChains {
			mutable.FilterChains[cnum].TCP = append(mutable.FilterChains[cnum].TCP, filter)
		}
		return nil
	}

	return fmt.Errorf("unknown listener type %v in mixer.OnOutboundListener", in.ListenerProtocol)
}

// OnInboundListener implements the Callbacks interface method.
func (mixerplugin) OnInboundListener(in *plugin.InputParams, mutable *plugin.MutableObjects) error {
	if in.Env.Mesh.MixerCheckServer == "" && in.Env.Mesh.MixerReportServer == "" {
		return nil
	}

	attrs := attributes{
		"destination.uid":       attrUID(in.Node),
		"destination.namespace": attrNamespace(in.Node),
		"context.reporter.uid":  attrUID(in.Node),
		"context.reporter.type": attrStringValue("inbound"),
	}

	switch address := mutable.Listener.Address.Address.(type) {
	case *core.Address_SocketAddress:
		if address != nil && address.SocketAddress != nil {
			attrs["destination.ip"] = attrIPValue(address.SocketAddress.Address)
			switch portSpec := address.SocketAddress.PortSpecifier.(type) {
			case *core.SocketAddress_PortValue:
				if portSpec != nil {
					attrs["destination.port"] = attrIntValue(int64(portSpec.PortValue))
				}
			}
		}
	}

	switch in.ListenerProtocol {
	case plugin.ListenerProtocolHTTP:
		filter := buildInboundHTTPFilter(in.Env.Mesh, in.Node, attrs)
		for cnum := range mutable.FilterChains {
			mutable.FilterChains[cnum].HTTP = append(mutable.FilterChains[cnum].HTTP, filter)
		}
		return nil
	case plugin.ListenerProtocolTCP:
		filter := buildInboundTCPFilter(in.Env.Mesh, in.Node, attrs, in.ProxyInstances)
		for cnum := range mutable.FilterChains {
			mutable.FilterChains[cnum].TCP = append(mutable.FilterChains[cnum].TCP, filter)
		}
		return nil
	}

	return fmt.Errorf("unknown listener type %v in mixer.OnOutboundListener", in.ListenerProtocol)
}

// OnOutboundCluster implements the Plugin interface method.
func (mixerplugin) OnOutboundCluster(env model.Environment, node model.Proxy, service *model.Service, servicePort *model.Port, cluster *xdsapi.Cluster) {
	// do nothing
}

// OnInboundCluster implements the Plugin interface method.
func (mixerplugin) OnInboundCluster(env model.Environment, node model.Proxy, service *model.Service, servicePort *model.Port, cluster *xdsapi.Cluster) {
	// do nothing
}

// OnOutboundRouteConfiguration implements the Plugin interface method.
func (mixerplugin) OnOutboundRouteConfiguration(in *plugin.InputParams, routeConfiguration *xdsapi.RouteConfiguration) {
	for i := 0; i < len(routeConfiguration.VirtualHosts); i++ {
		host := routeConfiguration.VirtualHosts[i]
		for j := 0; j < len(host.Routes); j++ {
			host.Routes[j] = modifyOutboundRouteConfig(in, host.Routes[j])
		}
		routeConfiguration.VirtualHosts[i] = host
	}
}

// OnInboundRouteConfiguration implements the Plugin interface method.
func (mixerplugin) OnInboundRouteConfiguration(in *plugin.InputParams, routeConfiguration *xdsapi.RouteConfiguration) {
	switch in.ListenerProtocol {
	case plugin.ListenerProtocolHTTP:
		// copy structs in place
		for i := 0; i < len(routeConfiguration.VirtualHosts); i++ {
			host := routeConfiguration.VirtualHosts[i]
			for j := 0; j < len(host.Routes); j++ {
				route := host.Routes[j]
				route.PerFilterConfig = addServiceConfig(route.PerFilterConfig, buildInboundRouteConfig(in, in.ServiceInstance))
				host.Routes[j] = route
			}
			routeConfiguration.VirtualHosts[i] = host
		}

	case plugin.ListenerProtocolTCP:
	default:
		log.Warn("Unknown listener type in mixer#OnOutboundRouteConfiguration")
	}
}

func buildTransport(mesh *meshconfig.MeshConfig, uid attribute) *mccpb.TransportConfig {
	policy, _, _ := net.SplitHostPort(mesh.MixerCheckServer)
	telemetry, _, _ := net.SplitHostPort(mesh.MixerReportServer)

	port := mixerPortNumber
	if mesh.AuthPolicy == meshconfig.MeshConfig_MUTUAL_TLS {
		port = mixerMTLSPortNumber
	}

	return &mccpb.TransportConfig{
		CheckCluster:  model.BuildSubsetKey(model.TrafficDirectionOutbound, "", model.Hostname(policy), port),
		ReportCluster: model.BuildSubsetKey(model.TrafficDirectionOutbound, "", model.Hostname(telemetry), port),
		// internal telemetry forwarding
		AttributesForMixerProxy: &mpb.Attributes{Attributes: attributes{"source.uid": uid}},
		// TODO(yangminzhu): Make this configurable in mesh config.
		NetworkFailPolicy: &mccpb.NetworkFailPolicy{Policy: mccpb.FAIL_CLOSE},
	}
}

func buildOutboundHTTPFilter(mesh *meshconfig.MeshConfig, attrs attributes, node *model.Proxy) *http_conn.HttpFilter {
	return &http_conn.HttpFilter{
		Name: mixer,
		Config: util.MessageToStruct(&mccpb.HttpClientConfig{
			MixerAttributes: &mpb.Attributes{Attributes: attrs},
			ForwardAttributes: &mpb.Attributes{Attributes: attributes{
				"source.uid": attrUID(node),
			}},
			Transport: buildTransport(mesh, attrUID(node)),
		}),
	}
}

func buildInboundHTTPFilter(mesh *meshconfig.MeshConfig, node *model.Proxy, attrs attributes) *http_conn.HttpFilter {
	ingress := "ingress"
	return &http_conn.HttpFilter{
		Name: mixer,
		Config: util.MessageToStruct(&mccpb.HttpClientConfig{
			DefaultDestinationService: ingress,
			ServiceConfigs: map[string]*mccpb.ServiceConfig{
				ingress: {
					DisableCheckCalls: mesh.DisablePolicyChecks,
				},
			},
			MixerAttributes: &mpb.Attributes{Attributes: attrs},
			Transport:       buildTransport(mesh, attrUID(node)),
		}),
	}
}

func modifyOutboundRouteConfig(in *plugin.InputParams, httpRoute route.Route) route.Route {
	// default config, to be overridden by per-weighted cluster
	httpRoute.PerFilterConfig = addServiceConfig(httpRoute.PerFilterConfig, &mccpb.ServiceConfig{
		DisableCheckCalls: disableClientPolicyChecks(in.Env.Mesh, in.Node),
	})
	switch action := httpRoute.Action.(type) {
	case *route.Route_Route:
		switch upstreams := action.Route.ClusterSpecifier.(type) {
		case *route.RouteAction_Cluster:
			_, _, hostname, _ := model.ParseSubsetKey(upstreams.Cluster)
			attrs := addDestinationServiceAttributes(make(attributes), in.Env.ServiceDiscovery, hostname)
			httpRoute.PerFilterConfig = addServiceConfig(httpRoute.PerFilterConfig, &mccpb.ServiceConfig{
				DisableCheckCalls: disableClientPolicyChecks(in.Env.Mesh, in.Node),
				MixerAttributes:   &mpb.Attributes{Attributes: attrs},
				ForwardAttributes: &mpb.Attributes{Attributes: attrs},
			})
		case *route.RouteAction_WeightedClusters:
			for _, weighted := range upstreams.WeightedClusters.Clusters {
				_, _, hostname, _ := model.ParseSubsetKey(weighted.Name)
				attrs := addDestinationServiceAttributes(make(attributes), in.Env.ServiceDiscovery, hostname)
				weighted.PerFilterConfig = addServiceConfig(weighted.PerFilterConfig, &mccpb.ServiceConfig{
					DisableCheckCalls: disableClientPolicyChecks(in.Env.Mesh, in.Node),
					MixerAttributes:   &mpb.Attributes{Attributes: attrs},
					ForwardAttributes: &mpb.Attributes{Attributes: attrs},
				})
			}
		case *route.RouteAction_ClusterHeader:
		default:
			log.Warn("Unknown cluster type in mixer#OnOutboundRouteConfiguration")
		}
	case *route.Route_Redirect, *route.Route_DirectResponse:
	default:
		log.Warn("Unknown route type in mixer#OnOutboundRouteConfiguration")
	}
	return httpRoute
}

func buildInboundRouteConfig(in *plugin.InputParams, instance *model.ServiceInstance) *mccpb.ServiceConfig {
	config := in.Env.IstioConfigStore

	attrs := addDestinationServiceAttributes(make(attributes), in.Env.ServiceDiscovery, instance.Service.Hostname)
	out := &mccpb.ServiceConfig{
		DisableCheckCalls: in.Env.Mesh.DisablePolicyChecks,
		MixerAttributes:   &mpb.Attributes{Attributes: attrs},
	}

	apiSpecs := config.HTTPAPISpecByDestination(instance)
	model.SortHTTPAPISpec(apiSpecs)
	for _, config := range apiSpecs {
		out.HttpApiSpec = append(out.HttpApiSpec, config.Spec.(*mccpb.HTTPAPISpec))
	}

	quotaSpecs := config.QuotaSpecByDestination(instance)
	model.SortQuotaSpec(quotaSpecs)
	for _, config := range quotaSpecs {
		out.QuotaSpec = append(out.QuotaSpec, config.Spec.(*mccpb.QuotaSpec))
	}

	return out
}

func buildOutboundTCPFilter(mesh *meshconfig.MeshConfig, attrsIn attributes, node *model.Proxy, destination *model.Service,
	discovery model.ServiceDiscovery) listener.Filter {
	attrs := attrsCopy(attrsIn)
	if destination != nil {
		attrs = addDestinationServiceAttributes(attrs, discovery, destination.Hostname)
	}
	return listener.Filter{
		Name: mixer,
		Config: util.MessageToStruct(&mccpb.TcpClientConfig{
			DisableCheckCalls: disableClientPolicyChecks(mesh, node),
			MixerAttributes:   &mpb.Attributes{Attributes: attrs},
			Transport:         buildTransport(mesh, attrUID(node)),
		}),
	}
}

func buildInboundTCPFilter(mesh *meshconfig.MeshConfig, node *model.Proxy, attrs attributes, instances []*model.ServiceInstance) listener.Filter {
	return listener.Filter{
		Name: mixer,
		Config: util.MessageToStruct(&mccpb.TcpClientConfig{
			DisableCheckCalls: mesh.DisablePolicyChecks,
			MixerAttributes:   &mpb.Attributes{Attributes: attrs},
			Transport:         buildTransport(mesh, attrUID(node)),
		}),
	}
}

func addServiceConfig(filterConfigs map[string]*types.Struct, config *mccpb.ServiceConfig) map[string]*types.Struct {
	if filterConfigs == nil {
		filterConfigs = make(map[string]*types.Struct)
	}
	filterConfigs[mixer] = util.MessageToStruct(config)
	return filterConfigs
}

func addDestinationServiceAttributes(attrs attributes, discovery model.ServiceDiscovery, destinationHostname model.Hostname) attributes {
	if destinationHostname == "" {
		return attrs
	}
	attrs["destination.service"] = attrStringValue(destinationHostname.String()) // DEPRECATED. Remove when fully out of use.
	attrs["destination.service.host"] = attrStringValue(destinationHostname.String())

	serviceAttributes, err := discovery.GetServiceAttributes(destinationHostname)
	if err != nil && serviceAttributes != nil {
		if serviceAttributes.Name != "" {
			attrs["destination.service.name"] = attrStringValue(serviceAttributes.Name)
		}
		if serviceAttributes.Namespace != "" {
			attrs["destination.service.namespace"] = attrStringValue(serviceAttributes.Namespace)
		}
		if serviceAttributes.UID != "" {
			attrs["destination.service.uid"] = attrStringValue(serviceAttributes.UID)
		}
	}
	return attrs
}

func disableClientPolicyChecks(mesh *meshconfig.MeshConfig, node *model.Proxy) bool {
	if mesh.DisablePolicyChecks {
		return true
	}
	if node.Type == model.Router {
		return false
	}
	if mesh.EnableClientSidePolicyCheck {
		return false
	}
	return true
}

func attrStringValue(value string) attribute {
	return &mpb.Attributes_AttributeValue{Value: &mpb.Attributes_AttributeValue_StringValue{StringValue: value}}
}

func attrUID(node *model.Proxy) attribute {
	return attrStringValue("kubernetes://" + node.ID)
}

func attrNamespace(node *model.Proxy) attribute {
	parts := strings.Split(node.ID, ".")
	if len(parts) >= 2 {
		return attrStringValue(parts[1])
	}
	return attrStringValue("")
}

func attrIntValue(value int64) attribute {
	return &mpb.Attributes_AttributeValue{Value: &mpb.Attributes_AttributeValue_Int64Value{Int64Value: value}}
}

func attrIPValue(ip string) attribute {
	return &mpb.Attributes_AttributeValue{Value: &mpb.Attributes_AttributeValue_BytesValue{BytesValue: net.ParseIP(ip)}}
}

func attrsCopy(attrs attributes) attributes {
	out := make(attributes)
	for k, v := range attrs {
		out[k] = v
	}
	return out
}
