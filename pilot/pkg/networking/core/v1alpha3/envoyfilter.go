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

package v1alpha3

import (
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	"net"
	"strings"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	xdsutil "github.com/envoyproxy/go-control-plane/pkg/util"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/plugin"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pkg/log"
)

// We process EnvoyFilter CRDs after calling all plugins and building the listener with the required filter chains
// Having the entire filter chain is essential because users can specify one or more filters to be inserted
// before/after  a filter or remove one or more filters.
// We use the plugin.InputParams as a convenience object to pass around parameters like proxy, proxyInstances, ports,
// etc., instead of having a long argument list
// If one or more filters are added to the HTTP connection manager, we will update the last filter in the listener
// filter chain (which is the http connection manager) with the updated object.
func insertUserFilters(in *plugin.InputParams, listener *xdsapi.Listener,
	httpConnectionManagers []*http_conn.HttpConnectionManager) error { //nolint: unparam
	filterCRD := getUserFiltersForWorkload(in)
	if filterCRD == nil {
		return nil
	}

	listenerIPAddress := getListenerIPAddress(&listener.Address)
	if listenerIPAddress == nil {
		log.Warnf("Failed to parse IP Address from plugin listener")
	}

	for _, f := range filterCRD.Filters {
		if !listenerMatch(in, listenerIPAddress, f.ListenerMatch) {
			continue
		}
		// 4 cases of filter insertion
		// http listener, http filter
		// tcp listener, tcp filter
		// http listener, tcp filter
		// tcp listener, http filter -- invalid

		for cnum, lFilterChain := range listener.FilterChains {
			if util.IsHTTPFilterChain(lFilterChain) {
				// The listener match logic does not take into account the listener protocol
				// because filter chains in a listener can have multiple protocols.
				// for each filter chain, if the filter chain has a http connection manager,
				// treat it as a http listener
				// ListenerProtocol defaults to ALL. But if user specified listener protocol TCP, then
				// skip this filter chain as its a HTTP filter chain
				if f.ListenerMatch != nil &&
					!(f.ListenerMatch.ListenerProtocol == networking.EnvoyFilter_ListenerMatch_ALL ||
						f.ListenerMatch.ListenerProtocol == networking.EnvoyFilter_ListenerMatch_HTTP) {
					continue
				}

				// Now that the match condition is true, insert the filter if compatible
				// http listener, http filter case
				if f.FilterType == networking.EnvoyFilter_Filter_HTTP {
					// Insert into http connection manager
					doHTTPFilterOperation(listener.Name, &listener.FilterChains[cnum], httpConnectionManagers[cnum], f, util.IsXDSMarshalingToAnyEnabled(in.Node))
				} else {
					// http listener, tcp filter
					doNetworkFilterOperation(listener.Name, &listener.FilterChains[cnum], f)
				}
			} else {
				// The listener match logic does not take into account the listener protocol
				// because filter chains in a listener can have multiple protocols.
				// for each filter chain, if the filter chain does not have a http connection manager,
				// treat it as a tcp listener
				// ListenerProtocol defaults to ALL. But if user specified listener protocol HTTP, then
				// skip this filter chain as its a TCP filter chain
				if f.ListenerMatch != nil &&
					!(f.ListenerMatch.ListenerProtocol == networking.EnvoyFilter_ListenerMatch_ALL ||
						f.ListenerMatch.ListenerProtocol == networking.EnvoyFilter_ListenerMatch_TCP) {
					continue
				}

				// treat both as insert network filter X into network filter chain.
				// We cannot insert a HTTP in filter in network filter chain.
				// Even HTTP connection manager is a network filter
				if f.FilterType == networking.EnvoyFilter_Filter_HTTP {
					log.Warnf("Ignoring filter %s. Cannot insert HTTP filter in network filter chain",
						f.FilterName)
					continue
				}
				doNetworkFilterOperation(listener.Name, &listener.FilterChains[cnum], f)
			}
		}
	}
	return nil
}

// NOTE: There can be only one filter for a workload. If multiple filters are defined, the behavior
// is undefined.
func getUserFiltersForWorkload(in *plugin.InputParams) *networking.EnvoyFilter {
	env := in.Env
	// collect workload labels
	workloadInstances := in.ProxyInstances

	var workloadLabels model.LabelsCollection
	for _, w := range workloadInstances {
		workloadLabels = append(workloadLabels, w.Labels)
	}

	f := env.EnvoyFilter(workloadLabels)
	if f != nil {
		return f.Spec.(*networking.EnvoyFilter)
	}
	return nil
}

func getListenerIPAddress(address *core.Address) net.IP {
	if address != nil && address.Address != nil {
		switch t := address.Address.(type) {
		case *core.Address_SocketAddress:
			if t.SocketAddress != nil {
				ip := "0.0.0.0"
				if t.SocketAddress.Address != "::" {
					ip = t.SocketAddress.Address
				}
				return net.ParseIP(ip)
			}
		}
	}
	return nil
}

func listenerMatch(in *plugin.InputParams, listenerIP net.IP,
	matchCondition *networking.EnvoyFilter_ListenerMatch) bool {
	if matchCondition == nil {
		return true
	}

	// match by port first
	if matchCondition.PortNumber > 0 && in.Port.Port != int(matchCondition.PortNumber) {
		return false
	}

	// match by port name prefix
	if matchCondition.PortNamePrefix != "" {
		if !strings.HasPrefix(strings.ToLower(in.Port.Name), strings.ToLower(matchCondition.PortNamePrefix)) {
			return false
		}
	}

	// case ANY implies do not care about proxy type or direction
	if matchCondition.ListenerType != networking.EnvoyFilter_ListenerMatch_ANY {
		// check if the current listener category matches with the user specified type
		if matchCondition.ListenerType != in.ListenerCategory {
			return false
		}

		// Check if the node's role matches properly with the listener category
		switch matchCondition.ListenerType {
		case networking.EnvoyFilter_ListenerMatch_GATEWAY:
			if in.Node.Type != model.Router {
				return false // We don't care about direction for gateways
			}
		case networking.EnvoyFilter_ListenerMatch_SIDECAR_INBOUND,
			networking.EnvoyFilter_ListenerMatch_SIDECAR_OUTBOUND:
			if in.Node.Type != model.SidecarProxy {
				return false
			}
		}
	}

	// Listener protocol will be matched as we try to insert the filters

	if len(matchCondition.Address) > 0 {
		if listenerIP == nil {
			// We failed to parse the listener IP address.
			// It could be a unix domain socket or something else.
			// Since we have some addresses to match against, this nil IP is considered as a mismatch
			return false
		}
		matched := false
		// if any of the addresses here match, return true
		for _, address := range matchCondition.Address {
			if strings.Contains(address, "/") {
				var ipNet *net.IPNet
				var err error
				if _, ipNet, err = net.ParseCIDR(address); err != nil {
					log.Warnf("Failed to parse address %s in EnvoyFilter: %v", address, err)
					continue
				}
				if ipNet.Contains(listenerIP) {
					matched = true
					break
				}
			} else if net.ParseIP(address).Equal(listenerIP) {
				matched = true
				break
			}
		}
		return matched
	}

	return true
}

func doHTTPFilterOperation(listenerName string, filterChain *listener.FilterChain, hcm *http_conn.HttpConnectionManager,
	envoyFilter *networking.EnvoyFilter_Filter, isXDSMarshalingToAnyEnabled bool) {

	if envoyFilter.Op == nil {
		insertHTTPFilter(listenerName, filterChain, hcm, envoyFilter, nil, isXDSMarshalingToAnyEnabled)
	}
	switch selector := envoyFilter.Op.(type) {
	case *networking.EnvoyFilter_Filter_InsertPosition:
		insertHTTPFilter(listenerName, filterChain, hcm, envoyFilter, selector.InsertPosition, isXDSMarshalingToAnyEnabled)
	case *networking.EnvoyFilter_Filter_Overwrite:
		overwriteOrMergeHTTPFilter(listenerName, filterChain, hcm, envoyFilter, false, isXDSMarshalingToAnyEnabled)
	case *networking.EnvoyFilter_Filter_Merge:
		overwriteOrMergeHTTPFilter(listenerName, filterChain, hcm, envoyFilter, true, isXDSMarshalingToAnyEnabled)
	}
}

func doNetworkFilterOperation(listenerName string, filterChain *listener.FilterChain,
	envoyFilter *networking.EnvoyFilter_Filter) {

	if envoyFilter.Op == nil {
		insertNetworkFilter(listenerName, filterChain, envoyFilter, nil)
	}
	switch selector := envoyFilter.Op.(type) {
	case *networking.EnvoyFilter_Filter_InsertPosition:
		insertNetworkFilter(listenerName, filterChain, envoyFilter, selector.InsertPosition)
	case *networking.EnvoyFilter_Filter_Overwrite:
		overwriteOrMergeNetworkFilter(listenerName, filterChain, envoyFilter, false)
	case *networking.EnvoyFilter_Filter_Merge:
		overwriteOrMergeNetworkFilter(listenerName, filterChain, envoyFilter, true)
	}
}

func insertHTTPFilter(listenerName string, filterChain *listener.FilterChain, hcm *http_conn.HttpConnectionManager,
	envoyFilter *networking.EnvoyFilter_Filter, insertPosition *networking.EnvoyFilter_InsertPosition, isXDSMarshalingToAnyEnabled bool) {
	filter := &http_conn.HttpFilter{
		Name:       envoyFilter.FilterName,
		ConfigType: &http_conn.HttpFilter_Config{Config: envoyFilter.FilterConfig},
	}

	position := networking.EnvoyFilter_InsertPosition_FIRST
	if insertPosition != nil {
		position = insertPosition.Index
	}

	oldLen := len(hcm.HttpFilters)
	switch position {
	case networking.EnvoyFilter_InsertPosition_FIRST, networking.EnvoyFilter_InsertPosition_BEFORE:
		hcm.HttpFilters = append([]*http_conn.HttpFilter{filter}, hcm.HttpFilters...)
		if position == networking.EnvoyFilter_InsertPosition_BEFORE {
			// bubble the filter to the right position scanning from beginning
			for i := 1; i < len(hcm.HttpFilters); i++ {
				if hcm.HttpFilters[i].Name != insertPosition.RelativeTo {
					hcm.HttpFilters[i-1], hcm.HttpFilters[i] = hcm.HttpFilters[i], hcm.HttpFilters[i-1]
				} else {
					break
				}
			}
		}
	case networking.EnvoyFilter_InsertPosition_LAST, networking.EnvoyFilter_InsertPosition_AFTER:
		hcm.HttpFilters = append(hcm.HttpFilters, filter)
		if position == networking.EnvoyFilter_InsertPosition_AFTER {
			// bubble the filter to the right position scanning from end
			for i := len(hcm.HttpFilters) - 2; i >= 0; i-- {
				if hcm.HttpFilters[i].Name != insertPosition.RelativeTo {
					hcm.HttpFilters[i+1], hcm.HttpFilters[i] = hcm.HttpFilters[i], hcm.HttpFilters[i+1]
				} else {
					break
				}
			}
		}
	}

	// Rebuild the HTTP connection manager in the network filter chain
	// Its the last filter in the filter chain
	filterStruct := listener.Filter{
		Name: xdsutil.HTTPConnectionManager,
	}
	if isXDSMarshalingToAnyEnabled {
		filterStruct.ConfigType = &listener.Filter_TypedConfig{TypedConfig: util.MessageToAny(hcm)}
	} else {
		filterStruct.ConfigType = &listener.Filter_Config{Config: util.MessageToStruct(hcm)}
	}
	filterChain.Filters[len(filterChain.Filters)-1] = filterStruct
	log.Debugf("EnvoyFilters: Rebuilt HTTP Connection Manager %s (from %d filters to %d filters)",
		listenerName, oldLen, len(hcm.HttpFilters))
}

func overwriteOrMergeHTTPFilter(listenerName string, filterChain *listener.FilterChain, hcm *http_conn.HttpConnectionManager,
	envoyFilter *networking.EnvoyFilter_Filter, isMerge bool, isXDSMarshalingToAnyEnabled bool) {

	for i := 1; i < len(hcm.HttpFilters); i++ {
		if hcm.HttpFilters[i].Name == envoyFilter.FilterName {
			if !isMerge {
				hcm.HttpFilters[i].ConfigType = &http_conn.HttpFilter_Config{Config: envoyFilter.FilterConfig}
			} else {
				switch selector := hcm.HttpFilters[i].ConfigType.(type) {
				case *http_conn.HttpFilter_Config:
					proto.Merge(selector.Config, envoyFilter.FilterConfig)
				case *http_conn.HttpFilter_TypedConfig:
					selector.TypedConfig, _ = mergeAnyWithStruct(listenerName, selector.TypedConfig, envoyFilter)
				}
			}
			break
		}
	}

	// Rebuild the HTTP connection manager in the network filter chain
	// Its the last filter in the filter chain
	filterStruct := listener.Filter{
		Name: xdsutil.HTTPConnectionManager,
	}
	if isXDSMarshalingToAnyEnabled {
		filterStruct.ConfigType = &listener.Filter_TypedConfig{TypedConfig: util.MessageToAny(hcm)}
	} else {
		filterStruct.ConfigType = &listener.Filter_Config{Config: util.MessageToStruct(hcm)}
	}
	filterChain.Filters[len(filterChain.Filters)-1] = filterStruct
	log.Debugf("EnvoyFilters: overwrote %s filter in HTTP Connection Manager %s", envoyFilter.FilterName,
		listenerName)
}

func insertNetworkFilter(listenerName string, filterChain *listener.FilterChain,
	envoyFilter *networking.EnvoyFilter_Filter, insertPosition *networking.EnvoyFilter_InsertPosition) {
	filter := &listener.Filter{
		Name:       envoyFilter.FilterName,
		ConfigType: &listener.Filter_Config{Config: envoyFilter.FilterConfig},
	}

	position := networking.EnvoyFilter_InsertPosition_FIRST
	if insertPosition != nil {
		position = insertPosition.Index
	}

	oldLen := len(filterChain.Filters)
	switch position {
	case networking.EnvoyFilter_InsertPosition_FIRST, networking.EnvoyFilter_InsertPosition_BEFORE:
		filterChain.Filters = append([]listener.Filter{*filter}, filterChain.Filters...)
		if position == networking.EnvoyFilter_InsertPosition_BEFORE {
			// bubble the filter to the right position scanning from beginning
			for i := 1; i < len(filterChain.Filters); i++ {
				if filterChain.Filters[i].Name != insertPosition.RelativeTo {
					filterChain.Filters[i-1], filterChain.Filters[i] = filterChain.Filters[i], filterChain.Filters[i-1]
					break
				}
			}
		}
	case networking.EnvoyFilter_InsertPosition_LAST, networking.EnvoyFilter_InsertPosition_AFTER:
		filterChain.Filters = append(filterChain.Filters, *filter)
		if position == networking.EnvoyFilter_InsertPosition_AFTER {
			// bubble the filter to the right position scanning from end
			for i := len(filterChain.Filters) - 2; i >= 0; i-- {
				if filterChain.Filters[i].Name != insertPosition.RelativeTo {
					filterChain.Filters[i+1], filterChain.Filters[i] = filterChain.Filters[i], filterChain.Filters[i+1]
					break
				}
			}
		}
	}
	log.Debugf("EnvoyFilters: Rebuilt network filter stack for listener %s (from %d filters to %d filters)",
		listenerName, oldLen, len(filterChain.Filters))
}

func overwriteOrMergeNetworkFilter(listenerName string, filterChain *listener.FilterChain,
	envoyFilter *networking.EnvoyFilter_Filter, isMerge bool) {

	for i := 1; i < len(filterChain.Filters); i++ {
		if filterChain.Filters[i].Name == envoyFilter.FilterName {
			if !isMerge {
				filterChain.Filters[i].ConfigType = &listener.Filter_Config{Config: envoyFilter.FilterConfig}
			} else {
				switch selector := filterChain.Filters[i].ConfigType.(type) {
				case *listener.Filter_Config:
					proto.Merge(selector.Config, envoyFilter.FilterConfig)
				case *listener.Filter_TypedConfig:
					selector.TypedConfig, _ = mergeAnyWithStruct(listenerName, selector.TypedConfig, envoyFilter)
				}
			}
			return
		}
	}
}

func mergeAnyWithStruct(listenerName string, any *types.Any, envoyFilter *networking.EnvoyFilter_Filter) (*types.Any, error) {
	// Assuming that Pilot is compiled with this type [which should always be the case]
	var err error
	var x types.DynamicAny

	// First get an object of type used by this message
	if err = types.UnmarshalAny(any, &x); err != nil {
		log.Debugf("EnvoyFilters: Failed to unmarshall built in filter %s (listener %s) from any type",
			envoyFilter.FilterName, listenerName)
		return any, err // retain old value
	}

	// Create a typed copy. We will convert the user's struct to this type
	temp := proto.Clone(x.Message)
	temp.Reset()
	if err = xdsutil.StructToMessage(envoyFilter.FilterConfig, temp); err != nil {
		log.Debugf("EnvoyFilters: Failed to convert user provided struct to typed filter %s (listener %s)",
			envoyFilter.FilterName, listenerName)
		return any, err
	}

	// Merge the two typed protos
	proto.Merge(x.Message, temp)
	var retVal *types.Any
	// Convert the merged proto back to any
	if retVal, err = types.MarshalAny(x.Message); err != nil {
		log.Debugf("EnvoyFilters: Failed to convert merged message to Any for filter %s (listener %s)",
			envoyFilter.FilterName, listenerName)
		return any, err
	}

	return retVal, nil
}
