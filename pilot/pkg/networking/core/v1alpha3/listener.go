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

package v1alpha3

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	accesslog "github.com/envoyproxy/go-control-plane/envoy/config/filter/accesslog/v2"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	tcp_proxy "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/tcp_proxy/v2"
	xdsutil "github.com/envoyproxy/go-control-plane/pkg/util"
	google_protobuf "github.com/gogo/protobuf/types"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/log"
)

const (
	fileAccessLog = "envoy.file_access_log"

	envoyHTTPConnectionManager = "envoy.http_connection_manager"

	// HTTPStatPrefix indicates envoy stat prefix for http listeners
	HTTPStatPrefix = "http"

	// RDSName is the name of route-discovery-service (RDS) cluster
	RDSName = "rds"

	// RDSHttpProxy is the special name for HTTP PROXY route
	RDSHttpProxy = "http_proxy"

	// VirtualListenerName is the name for traffic capture listener
	VirtualListenerName = "virtual"

	// WildcardAddress binds to all IP addresses
	WildcardAddress = "0.0.0.0"

	// LocalhostAddress for local binding
	LocalhostAddress = "127.0.0.1"
)

var (
	// Very verbose output in the logs - full LDS response logged for each sidecar.
	// Use /debug/ldsz instead.
	verboseDebug = os.Getenv("PILOT_DUMP_ALPHA3") != ""
)

// ListenersALPNProtocols denotes the the list of ALPN protocols that the listener
// should expose
var ListenersALPNProtocols = []string{"h2", "http/1.1"}

// BuildListeners produces a list of listeners and referenced clusters for all proxies
func (configgen *ConfigGeneratorImpl) BuildListeners(env model.Environment, node model.Proxy) ([]*xdsapi.Listener, error) {
	switch node.Type {
	case model.Sidecar:
		return configgen.buildSidecarListeners(env, node)
	case model.Router, model.Ingress:
		// TODO: add listeners for other protocols too
		return configgen.buildGatewayListeners(env, node)
	}
	return nil, nil
}

// buildSidecarListeners produces a list of listeners for sidecar proxies
func (configgen *ConfigGeneratorImpl) buildSidecarListeners(env model.Environment, node model.Proxy) ([]*xdsapi.Listener, error) {

	mesh := env.Mesh
	managementPorts := env.ManagementPorts(node.IPAddress)

	proxyInstances, err := env.GetProxyServiceInstances(node)
	if err != nil {
		return nil, err
	}

	services, err := env.Services()
	if err != nil {
		return nil, err
	}

	// ensure services are ordered to simplify generation logic
	sort.Slice(services, func(i, j int) bool { return services[i].Hostname < services[j].Hostname })

	listeners := make([]*xdsapi.Listener, 0)

	if mesh.ProxyListenPort > 0 {
		inbound := configgen.buildSidecarInboundListeners(env, node, proxyInstances)
		outbound := configgen.buildSidecarOutboundListeners(env, node, proxyInstances, services)

		listeners = append(listeners, inbound...)
		listeners = append(listeners, outbound...)

		mgmtListeners := buildMgmtPortListeners(managementPorts, node.IPAddress)
		// If management listener port and service port are same, bad things happen
		// when running in kubernetes, as the probes stop responding. So, append
		// non overlapping listeners only.
		for i := range mgmtListeners {
			m := mgmtListeners[i]
			l := util.GetByAddress(listeners, m.Address.String())
			if l != nil {
				log.Warnf("Omitting listener for management address %s (%s) due to collision with service listener %s (%s)",
					m.Name, m.Address, l.Name, l.Address)
				continue
			}
			listeners = append(listeners, m)
		}

		// We need a dummy filter to fill in the filter stack for orig_dst listener
		// TODO: Move to Listener filters and set up original dst filter there.
		dummyTCPProxy := &tcp_proxy.TcpProxy{
			StatPrefix: "Dummy",
			Cluster:    "Dummy",
		}

		// add an extra listener that binds to the port that is the recipient of the iptables redirect
		listeners = append(listeners, &xdsapi.Listener{
			Name:           VirtualListenerName,
			Address:        util.BuildAddress(WildcardAddress, uint32(mesh.ProxyListenPort)),
			UseOriginalDst: &google_protobuf.BoolValue{true},
			FilterChains: []listener.FilterChain{
				{
					Filters: []listener.Filter{
						{
							Name:   xdsutil.TCPProxy,
							Config: util.MessageToStruct(dummyTCPProxy),
						},
					},
				},
			},
		})
	}

	// enable HTTP PROXY port if necessary; this will add an RDS route for this port
	if mesh.ProxyHttpPort > 0 {
		useRemoteAddress := false
		traceOperation := http_conn.EGRESS
		listenAddress := LocalhostAddress

		if node.Type == model.Router {
			useRemoteAddress = true
			traceOperation = http_conn.INGRESS
			listenAddress = WildcardAddress
		}

		opts := buildListenerOpts{
			env:            env,
			proxy:          node,
			proxyInstances: proxyInstances,
			ip:             listenAddress,
			port:           int(mesh.ProxyHttpPort),
			protocol:       model.ProtocolHTTP,
			filterChainOpts: []*filterChainOpts{{
				httpOpts: &httpListenerOpts{
					routeConfig: configgen.BuildSidecarOutboundHTTPRouteConfig(env, node, proxyInstances,
						services, RDSHttpProxy),
					//rds:              RDSHttpProxy,
					useRemoteAddress: useRemoteAddress,
					direction:        traceOperation,
				},
			}},
		}
		l := buildListener(opts)
		if err := marshalFilters(l, opts, []plugin.FilterChain{{}}); err != nil {
			log.Warna("buildSidecarListeners ", err.Error())
		}
		listeners = append(listeners, l)
		// TODO: need inbound listeners in HTTP_PROXY case, with dedicated ingress listener.
	}

	return listeners, nil
}

// buildSidecarInboundListeners creates listeners for the server-side (inbound)
// configuration for co-located service proxyInstances.
func (configgen *ConfigGeneratorImpl) buildSidecarInboundListeners(env model.Environment, node model.Proxy,
	proxyInstances []*model.ServiceInstance) []*xdsapi.Listener {

	var listeners []*xdsapi.Listener
	listenerMap := make(map[string]*xdsapi.Listener)
	// inbound connections/requests are redirected to the endpoint address but appear to be sent
	// to the service address.
	for _, instance := range proxyInstances {
		endpoint := instance.Endpoint
		protocol := endpoint.ServicePort.Protocol

		// Local service instances can be accessed through one of three
		// addresses: localhost, endpoint IP, and service
		// VIP. Localhost bypasses the proxy and doesn't need any TCP
		// route config. Endpoint IP is handled below and Service IP is handled
		// by outbound routes.
		// Traffic sent to our service VIP is redirected by remote
		// services' kubeproxy to our specific endpoint IP.
		var listenerType plugin.ListenerType
		listenerOpts := buildListenerOpts{
			env:            env,
			proxy:          node,
			proxyInstances: proxyInstances,
			ip:             endpoint.Address,
			port:           endpoint.Port,
			protocol:       protocol,
		}

		listenerMapKey := fmt.Sprintf("%s:%d", endpoint.Address, endpoint.Port)
		if l, exists := listenerMap[listenerMapKey]; exists {
			log.Warnf("Conflicting inbound listeners on %s: previous listener %s", listenerMapKey, l.Name)
			// Skip building listener for the same ip port
			continue
		}

		switch protocol {
		case model.ProtocolHTTP, model.ProtocolHTTP2, model.ProtocolGRPC:
			listenerType = plugin.ListenerTypeHTTP
			listenerOpts.filterChainOpts = []*filterChainOpts{{
				httpOpts: &httpListenerOpts{
					routeConfig:      configgen.buildSidecarInboundHTTPRouteConfig(env, node, instance),
					rds:              "",
					useRemoteAddress: false,
					direction:        http_conn.INGRESS,
				}},
			}
		case model.ProtocolTCP, model.ProtocolHTTPS, model.ProtocolMongo, model.ProtocolRedis:
			listenerType = plugin.ListenerTypeTCP
			listenerOpts.filterChainOpts = []*filterChainOpts{{
				networkFilters: buildInboundNetworkFilters(instance),
			}}

		default:
			log.Debugf("Unsupported inbound protocol %v for port %#v", protocol, instance.Endpoint.ServicePort)
		}

		// call plugins
		l := buildListener(listenerOpts)
		mutable := &plugin.MutableObjects{
			Listener:     l,
			FilterChains: make([]plugin.FilterChain, len(l.FilterChains)),
		}
		for _, p := range configgen.Plugins {
			params := &plugin.InputParams{
				ListenerType:    listenerType,
				Env:             &env,
				Node:            &node,
				ServiceInstance: instance,
			}
			if err := p.OnInboundListener(params, mutable); err != nil {
				log.Warn(err.Error())
			}
		}
		// Filters are serialized one time into an opaque struct once we have the complete list.
		if err := marshalFilters(mutable.Listener, listenerOpts, mutable.FilterChains); err != nil {
			log.Warna("buildSidecarInboundListeners ", err.Error())
		}

		listeners = append(listeners, mutable.Listener)
		listenerMap[listenerMapKey] = mutable.Listener

	}
	return listeners
}

// buildSidecarOutboundListeners generates http and tcp listeners for outbound connections from the service instance
// TODO(github.com/istio/pilot/issues/237)
//
// Sharing tcp_proxy and http_connection_manager filters on the same port for
// different destination services doesn't work with Envoy (yet). When the
// tcp_proxy filter's route matching fails for the http service the connection
// is closed without falling back to the http_connection_manager.
//
// Temporary workaround is to add a listener for each service IP that requires
// TCP routing
//
// Connections to the ports of non-load balanced services are directed to
// the connection's original destination. This avoids costly queries of instance
// IPs and ports, but requires that ports of non-load balanced service be unique.
func (configgen *ConfigGeneratorImpl) buildSidecarOutboundListeners(env model.Environment, node model.Proxy,
	proxyInstances []*model.ServiceInstance, services []*model.Service) []*xdsapi.Listener {

	var tcpListeners, httpListeners []*xdsapi.Listener

	listenerMap := make(map[string]*xdsapi.Listener)
	for _, service := range services {
		for _, servicePort := range service.Ports {
			clusterName := model.BuildSubsetKey(model.TrafficDirectionOutbound, "",
				service.Hostname, servicePort)

			listenAddress := WildcardAddress
			var addresses []string
			var listenerMapKey string
			listenerOpts := buildListenerOpts{
				env:            env,
				proxy:          node,
				proxyInstances: proxyInstances,
				ip:             WildcardAddress,
				port:           servicePort.Port,
				protocol:       servicePort.Protocol,
			}

			switch servicePort.Protocol {
			// TODO: Set SNI for HTTPS
			case model.ProtocolHTTP2, model.ProtocolHTTP, model.ProtocolGRPC:
				listenerMapKey = fmt.Sprintf("%s:%d", listenAddress, servicePort.Port)
				if l, exists := listenerMap[listenerMapKey]; exists {
					if !strings.HasPrefix(l.Name, "http") {
						log.Warnf("Conflicting outbound listeners on %s: previous listener %s", listenerMapKey, l.Name)
					}
					// Skip building listener for the same http port
					continue
				}

				operation := http_conn.EGRESS
				useRemoteAddress := false

				if node.Type == model.Router {
					// if this is in Router mode, then use ingress style trace operation, and remote address settings
					useRemoteAddress = true
					operation = http_conn.INGRESS
				}

				listenerOpts.protocol = model.ProtocolHTTP
				listenerOpts.filterChainOpts = []*filterChainOpts{{
					httpOpts: &httpListenerOpts{
						//rds:              fmt.Sprintf("%d", servicePort.Port),
						routeConfig: configgen.BuildSidecarOutboundHTTPRouteConfig(
							env, node, proxyInstances, services, fmt.Sprintf("%d", servicePort.Port)),
						useRemoteAddress: useRemoteAddress,
						direction:        operation,
					},
				}}
			default:
				log.Infof("buildSidecarOutboundListeners: service %q has unknown protocol %#v, defaulting to TCP", service.Hostname, servicePort)
				fallthrough
			case model.ProtocolTCP, model.ProtocolHTTPS, model.ProtocolMongo, model.ProtocolRedis:
				if service.Resolution != model.Passthrough {
					listenAddress = service.Address
					addresses = []string{service.Address}
				}

				listenerMapKey = fmt.Sprintf("%s:%d", listenAddress, servicePort.Port)
				if _, exists := listenerMap[listenerMapKey]; exists {
					log.Warnf("Multiple TCP listener definitions for %s", listenerMapKey)
					continue
				}
				listenerOpts.filterChainOpts = []*filterChainOpts{{
					networkFilters: buildOutboundNetworkFilters(clusterName, addresses, servicePort),
				}}
			}

			// call plugins

			listenerOpts.ip = listenAddress
			l := buildListener(listenerOpts)
			mutable := &plugin.MutableObjects{
				Listener:     l,
				FilterChains: make([]plugin.FilterChain, len(l.FilterChains)),
			}

			for _, p := range configgen.Plugins {
				params := &plugin.InputParams{
					ListenerType: plugin.ModelProtocolToListenerType(servicePort.Protocol),
					Env:          &env,
					Node:         &node,
					Service:      service,
				}

				if err := p.OnOutboundListener(params, mutable); err != nil {
					log.Warn(err.Error())
				}
			}

			// Filters are serialized one time into an opaque struct once we have the complete list.
			if err := marshalFilters(mutable.Listener, listenerOpts, mutable.FilterChains); err != nil {
				log.Warna("buildSidecarOutboundListeners: ", err.Error())
			}

			// By default we require SNI; if there's only one filter chain then we know there's either 0 or 1 cert,
			// therefore SNI is not required.
			if len(mutable.Listener.FilterChains) == 1 && mutable.Listener.FilterChains[0].TlsContext != nil {
				mutable.Listener.FilterChains[0].TlsContext.RequireSni = boolFalse
			}

			if log.DebugEnabled() && len(mutable.Listener.FilterChains) > 1 {
				log.Debuga("buildSidecarOutboundListeners: multiple filter chain listener: ", mutable.Listener.Name)
			}

			listenerMap[listenerMapKey] = mutable.Listener
		}
	}

	for name, l := range listenerMap {
		if strings.HasPrefix(name, "tcp") {
			tcpListeners = append(tcpListeners, l)
		} else {
			httpListeners = append(httpListeners, l)
		}
	}

	return append(tcpListeners, httpListeners...)
}

// buildMgmtPortListeners creates inbound TCP only listeners for the management ports on
// server (inbound). Management port listeners are slightly different from standard Inbound listeners
// in that, they do not have mixer filters nor do they have inbound auth.
// N.B. If a given management port is same as the service instance's endpoint port
// the pod will fail to start in Kubernetes, because the mixer service tries to
// lookup the service associated with the Pod. Since the pod is yet to be started
// and hence not bound to the service), the service lookup fails causing the mixer
// to fail the health check call. This results in a vicious cycle, where kubernetes
// restarts the unhealthy pod after successive failed health checks, and the mixer
// continues to reject the health checks as there is no service associated with
// the pod.
// So, if a user wants to use kubernetes probes with Istio, she should ensure
// that the health check ports are distinct from the service ports.
func buildMgmtPortListeners(managementPorts model.PortList, managementIP string) []*xdsapi.Listener {
	listeners := make([]*xdsapi.Listener, 0, len(managementPorts))

	if managementIP == "" {
		managementIP = "127.0.0.1"
	}

	// assumes that inbound connections/requests are sent to the endpoint address
	for _, mPort := range managementPorts {
		switch mPort.Protocol {
		case model.ProtocolHTTP, model.ProtocolHTTP2, model.ProtocolGRPC, model.ProtocolTCP,
			model.ProtocolHTTPS, model.ProtocolMongo, model.ProtocolRedis:

			instance := &model.ServiceInstance{
				Endpoint: model.NetworkEndpoint{
					Address:     managementIP,
					Port:        mPort.Port,
					ServicePort: mPort,
				},
				Service: &model.Service{
					Hostname: ManagementClusterHostname,
				},
			}
			listenerOpts := buildListenerOpts{
				ip:       managementIP,
				port:     mPort.Port,
				protocol: model.ProtocolTCP,
				filterChainOpts: []*filterChainOpts{{
					networkFilters: buildInboundNetworkFilters(instance),
				}},
			}
			l := buildListener(listenerOpts)
			// TODO: should we call plugins for the admin port listeners too? We do everywhere else we contruct listeners.
			if err := marshalFilters(l, listenerOpts, []plugin.FilterChain{{}}); err != nil {
				log.Warna("buildMgmtPortListeners ", err.Error())
			}
			listeners = append(listeners, l)
		default:
			log.Warnf("Unsupported inbound protocol %v for management port %#v",
				mPort.Protocol, mPort)
		}
	}

	return listeners
}

// httpListenerOpts are options for an HTTP listener
type httpListenerOpts struct {
	//nolint: maligned
	routeConfig      *xdsapi.RouteConfiguration
	rds              string
	useRemoteAddress bool
	direction        http_conn.HttpConnectionManager_Tracing_OperationName
}

// filterChainOpts describes a filter chain: a set of filters with the same TLS context
type filterChainOpts struct {
	sniHosts       []string
	tlsContext     *auth.DownstreamTlsContext
	httpOpts       *httpListenerOpts
	networkFilters []listener.Filter
}

// buildListenerOpts are the options required to build a Listener
type buildListenerOpts struct {
	// nolint: maligned
	env             model.Environment
	proxy           model.Proxy
	proxyInstances  []*model.ServiceInstance
	ip              string
	port            int
	protocol        model.Protocol
	bindToPort      bool
	filterChainOpts []*filterChainOpts
}

func buildHTTPConnectionManager(mesh *meshconfig.MeshConfig, httpOpts *httpListenerOpts, httpFilters []*http_conn.HttpFilter) *http_conn.HttpConnectionManager {
	filters := append(httpFilters,
		&http_conn.HttpFilter{Name: xdsutil.CORS},
		&http_conn.HttpFilter{Name: xdsutil.Router},
		// TODO: need alphav3 fault filters.
		//buildFaultFilters(opts.config, opts.env, opts.proxy)...
	)

	refresh := time.Duration(mesh.RdsRefreshDelay.Seconds) * time.Second
	if refresh == 0 {
		// envoy crashes if 0. Will go away once we move to v2
		refresh = 5 * time.Second
	}

	connectionManager := &http_conn.HttpConnectionManager{
		CodecType: http_conn.AUTO,
		AccessLog: []*accesslog.AccessLog{
			{
				Config: nil,
			},
		},
		HttpFilters:      filters,
		StatPrefix:       HTTPStatPrefix,
		UseRemoteAddress: &google_protobuf.BoolValue{httpOpts.useRemoteAddress},
	}

	// not enabled yet
	if httpOpts.rds != "" {
		rds := &http_conn.HttpConnectionManager_Rds{
			Rds: &http_conn.Rds{
				RouteConfigName: httpOpts.rds,
				ConfigSource: core.ConfigSource{
					ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
						ApiConfigSource: &core.ApiConfigSource{
							ApiType:      core.ApiConfigSource_REST_LEGACY,
							ClusterNames: []string{RDSName},
							RefreshDelay: &refresh,
						},
					},
				},
			},
		}
		connectionManager.RouteSpecifier = rds
	} else {
		connectionManager.RouteSpecifier = &http_conn.HttpConnectionManager_RouteConfig{RouteConfig: httpOpts.routeConfig}
	}

	if connectionManager.RouteSpecifier == nil {
		connectionManager.RouteSpecifier = &http_conn.HttpConnectionManager_RouteConfig{
			RouteConfig: httpOpts.routeConfig,
		}
	}

	if mesh.AccessLogFile != "" {
		fl := &accesslog.FileAccessLog{
			Path: mesh.AccessLogFile,
		}

		connectionManager.AccessLog = []*accesslog.AccessLog{
			{
				Config: util.MessageToStruct(fl),
				Name:   fileAccessLog,
			},
		}
	}

	if mesh.EnableTracing {
		connectionManager.Tracing = &http_conn.HttpConnectionManager_Tracing{
			OperationName: httpOpts.direction,
		}
		connectionManager.GenerateRequestId = &google_protobuf.BoolValue{true}
	}

	if verboseDebug {
		connectionManagerJSON, _ := json.MarshalIndent(connectionManager, "  ", "  ")
		log.Infof("LDS: %s \n", string(connectionManagerJSON))
	}
	return connectionManager
}

// buildListener builds and initializes a Listener proto based on the provided opts. It does not set any filters.
func buildListener(opts buildListenerOpts) *xdsapi.Listener {
	filterChains := make([]listener.FilterChain, 0, len(opts.filterChainOpts))
	for _, chain := range opts.filterChainOpts {
		match := &listener.FilterChainMatch{}
		if len(chain.sniHosts) > 0 {
			match.SniDomains = chain.sniHosts
		}
		filterChains = append(filterChains, listener.FilterChain{
			FilterChainMatch: match,
			TlsContext:       chain.tlsContext,
		})
	}

	var deprecatedV1 *xdsapi.Listener_DeprecatedV1
	if !opts.bindToPort {
		deprecatedV1 = &xdsapi.Listener_DeprecatedV1{
			BindToPort: boolFalse,
		}
	}

	return &xdsapi.Listener{
		// protocol is either TCP or HTTP
		Name:         fmt.Sprintf("%s_%s_%d", protocolToListenerPrefix(opts.protocol), opts.ip, opts.port),
		Address:      util.BuildAddress(opts.ip, uint32(opts.port)),
		FilterChains: filterChains,
		DeprecatedV1: deprecatedV1,
	}
}

// marshalFilters adds the provided TCP and HTTP filters to the provided Listener and serializes them.
//
// TODO: should we change this from []plugins.FilterChains to [][]listener.Filter, [][]*http_conn.HttpFilter?
// TODO: given how tightly tied listener.FilterChains, opts.filterChainOpts, and mutable.FilterChains are to eachother
// we should encapsulate them some way to ensure they remain consistent (mainly that in each an index refers to the same
// chain)
func marshalFilters(l *xdsapi.Listener, opts buildListenerOpts, chains []plugin.FilterChain) error {
	if len(opts.filterChainOpts) != len(chains) || len(chains) != len(l.FilterChains) || len(opts.filterChainOpts) == 0 {
		return fmt.Errorf("must have same number of chains in: \nlistener: %d; %#v\nopts: %d; %#v\nchain: %d; %#v",
			len(l.FilterChains), l, len(opts.filterChainOpts), opts, len(chains), chains)
	}

	for i, chain := range chains {
		opt := opts.filterChainOpts[i]
		// check that we either have all TCP or all HTTP chain, and not a mix
		// TODO: remove when Envoy supports port protocol multiplexing
		if (len(chain.TCP) > 0 || len(opt.networkFilters) > 0) && (len(chain.HTTP) > 0 || opt.httpOpts != nil) {
			return fmt.Errorf("listener %q filter chain %d cannot set both network(%#v) and HTTP(%#v) filter chains",
				l.Name, i, append(chain.TCP, opt.networkFilters...), chain.HTTP)
		}

		l.FilterChains[i].Filters = append(l.FilterChains[i].Filters, chain.TCP...)
		l.FilterChains[i].Filters = append(l.FilterChains[i].Filters, opt.networkFilters...)
		if log.DebugEnabled() {
			log.Debugf("attached %d network filters to listener %q filter chain %d", len(chain.TCP)+len(opt.networkFilters), l.Name, i)
		}

		if opt.httpOpts != nil {
			connectionManager := buildHTTPConnectionManager(opts.env.Mesh, opt.httpOpts, chain.HTTP)
			l.FilterChains[i].Filters = append(l.FilterChains[i].Filters, listener.Filter{
				Name:   envoyHTTPConnectionManager,
				Config: util.MessageToStruct(connectionManager),
			})
			log.Debugf("attached HTTP filter with %d http_filter options to listener %q filter chain %d", 1+len(chain.HTTP), l.Name, i)
		}
	}
	return nil
}

func protocolToListenerPrefix(p model.Protocol) string {
	if p.IsHTTP() {
		return "http"
	}
	return "tcp"
}
