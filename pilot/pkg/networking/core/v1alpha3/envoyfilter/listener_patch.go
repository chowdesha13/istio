// Copyright 2019 Istio Authors
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

package envoyfilter

import (
	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	xdslistener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/config/filter/network/http_connection_manager/v2"
	xdsutil "github.com/envoyproxy/go-control-plane/pkg/util"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/networking/util"
)

// ApplyListenerPatches applies patches to LDS output
func ApplyListenerPatches(patchContext networking.EnvoyFilter_PatchContext,
	proxy *model.Proxy, push *model.PushContext, listeners []*xdsapi.Listener, skipAdds bool) []*xdsapi.Listener {

	envoyFilterWrappers := push.EnvoyFilters(proxy)
	doListenerListOperation(patchContext, envoyFilterWrappers, listeners, skipAdds)
	return listeners
}

func doListenerListOperation(patchContext networking.EnvoyFilter_PatchContext,
	envoyFilterWrappers []*model.EnvoyFilterWrapper,
	listeners []*xdsapi.Listener, skipAdds bool) []*xdsapi.Listener {
	listenersRemoved := false
	for _, efw := range envoyFilterWrappers {
		// do all the changes for a single envoy filter crd object. [including adds]
		// then move on to the next one

		// only removes/merges plus next level object operations [add/remove/merge]
		for _, listener := range listeners {
			if listener.Name == "" {
				// removed by another op
				continue
			}
			doListenerOperation(patchContext, efw.Patches, listener, &listenersRemoved)
		}
		// adds at listener level if enabled
		if skipAdds {
			continue
		}
		for _, cp := range efw.Patches[networking.EnvoyFilter_LISTENER] {
			if !patchContextMatch(patchContext, cp) {
				continue
			}
			if cp.Operation == networking.EnvoyFilter_Patch_ADD ||
				cp.Operation == networking.EnvoyFilter_Patch_INSERT_AFTER ||
				cp.Operation == networking.EnvoyFilter_Patch_INSERT_BEFORE {
				listeners = append(listeners, cp.Value.(*xdsapi.Listener))
			}
		}
	}
	if listenersRemoved {
		tempArray := make([]*xdsapi.Listener, 0, len(listeners))
		for _, l := range listeners {
			if l.Name != "" {
				tempArray = append(tempArray, l)
			}
		}
		return tempArray
	}
	return listeners
}

func doListenerOperation(patchContext networking.EnvoyFilter_PatchContext,
	patches map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper,
	listener *xdsapi.Listener, listenersRemoved *bool) {
	for _, cp := range patches[networking.EnvoyFilter_LISTENER] {
		if !patchContextMatch(patchContext, cp) ||
			!listenerMatch(patchContext, listener, cp) {
			continue
		}

		if cp.Operation == networking.EnvoyFilter_Patch_REMOVE {
			listener.Name = ""
			*listenersRemoved = true
			// terminate the function here as we have nothing more do to for this listener
			return
		} else if cp.Operation == networking.EnvoyFilter_Patch_MERGE {
			proto.Merge(listener, cp.Value)
		}
	}

	doFilterChainListOperation(patchContext, patches, listener)
}

func doFilterChainListOperation(patchContext networking.EnvoyFilter_PatchContext,
	patches map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper,
	listener *xdsapi.Listener) {
	filterChainsRemoved := false
	for _, fc := range listener.FilterChains {
		if fc.Filters == nil {
			continue
		}
		doFilterChainOperation(patchContext, patches, listener, &fc, &filterChainsRemoved)
	}
	for _, cp := range patches[networking.EnvoyFilter_FILTER_CHAIN] {
		if !patchContextMatch(patchContext, cp) ||
			!listenerMatch(patchContext, listener, cp) {
			continue
		}

		if cp.Operation == networking.EnvoyFilter_Patch_ADD ||
			cp.Operation == networking.EnvoyFilter_Patch_INSERT_AFTER ||
			cp.Operation == networking.EnvoyFilter_Patch_INSERT_BEFORE {
			listener.FilterChains = append(listener.FilterChains, *cp.Value.(*xdslistener.FilterChain))
		}
	}
	if filterChainsRemoved {
		tempArray := make([]xdslistener.FilterChain, 0, len(listener.FilterChains))
		for _, fc := range listener.FilterChains {
			if fc.Filters != nil {
				tempArray = append(tempArray, fc)
			}
		}
		listener.FilterChains = tempArray
	}
}

func doFilterChainOperation(patchContext networking.EnvoyFilter_PatchContext,
	patches map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper,
	listener *xdsapi.Listener,
	fc *xdslistener.FilterChain, filterChainRemoved *bool) {
	for _, cp := range patches[networking.EnvoyFilter_FILTER_CHAIN] {
		if !patchContextMatch(patchContext, cp) ||
			!listenerMatch(patchContext, listener, cp) ||
			!filterChainMatch(fc, cp) {
			continue
		}
		if cp.Operation == networking.EnvoyFilter_Patch_REMOVE {
			fc.Filters = nil
			*filterChainRemoved = true
			// nothing more to do in other patches as we removed this filter chain
			return
		} else if cp.Operation == networking.EnvoyFilter_Patch_MERGE {
			proto.Merge(fc, cp.Value)
		}
	}
	doNetworkFilterListOperation(patchContext, patches, listener, fc)
}

func doNetworkFilterListOperation(patchContext networking.EnvoyFilter_PatchContext,
	patches map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper,
	listener *xdsapi.Listener, fc *xdslistener.FilterChain) {
	networkFiltersRemoved := false
	for _, filter := range fc.Filters {
		if filter.Name == "" {
			continue
		}
		doNetworkFilterOperation(patchContext, patches, listener, fc, &filter, &networkFiltersRemoved)
	}
	for _, cp := range patches[networking.EnvoyFilter_NETWORK_FILTER] {
		if !patchContextMatch(patchContext, cp) ||
			!listenerMatch(patchContext, listener, cp) ||
			!filterChainMatch(fc, cp) {
			continue
		}

		if cp.Operation == networking.EnvoyFilter_Patch_ADD {
			fc.Filters = append(fc.Filters, *cp.Value.(*xdslistener.Filter))
		} else if cp.Operation == networking.EnvoyFilter_Patch_INSERT_AFTER {
			fc.Filters = append(fc.Filters, *cp.Value.(*xdslistener.Filter))
			for i := len(fc.Filters) - 2; i >= 1; i-- {
				if !networkFilterMatch(&fc.Filters[i], cp) {
					fc.Filters[i-1], fc.Filters[i] = fc.Filters[i], fc.Filters[i-1]
				} else {
					break
				}
			}
		} else if cp.Operation == networking.EnvoyFilter_Patch_INSERT_BEFORE {
			fc.Filters = append(fc.Filters, *cp.Value.(*xdslistener.Filter))
			for i := len(fc.Filters) - 2; i >= 1; i-- {
				match := networkFilterMatch(&fc.Filters[i], cp)
				fc.Filters[i-1], fc.Filters[i] = fc.Filters[i], fc.Filters[i-1]
				if match {
					break
				}
			}
		}
	}
	if networkFiltersRemoved {
		tempArray := make([]xdslistener.Filter, 0, len(fc.Filters))
		for _, filter := range fc.Filters {
			if filter.Name != "" {
				tempArray = append(tempArray, filter)
			}
		}
		fc.Filters = tempArray
	}
}

func doNetworkFilterOperation(patchContext networking.EnvoyFilter_PatchContext,
	patches map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper,
	listener *xdsapi.Listener, fc *xdslistener.FilterChain,
	filter *xdslistener.Filter, networkFilterRemoved *bool) {
	for _, cp := range patches[networking.EnvoyFilter_NETWORK_FILTER] {
		if !patchContextMatch(patchContext, cp) ||
			!listenerMatch(patchContext, listener, cp) ||
			!filterChainMatch(fc, cp) ||
			!networkFilterMatch(filter, cp) {
			continue
		}
		if cp.Operation == networking.EnvoyFilter_Patch_REMOVE {
			filter.Name = ""
			*networkFilterRemoved = true
			// nothing more to do in other patches as we removed this filter
			return
		} else if cp.Operation == networking.EnvoyFilter_Patch_MERGE {
			proto.Merge(filter, cp.Value)
		}
	}
	if filter.Name == xdsutil.HTTPConnectionManager {
		doHTTPFilterListOperation(patchContext, patches, listener, fc, filter)
	}
}

func doHTTPFilterListOperation(patchContext networking.EnvoyFilter_PatchContext,
	patches map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper,
	listener *xdsapi.Listener, fc *xdslistener.FilterChain, filter *xdslistener.Filter) {
	hcm := &http_conn.HttpConnectionManager{}
	if filter.GetTypedConfig() != nil {
		if err := types.UnmarshalAny(filter.GetTypedConfig(), hcm); err != nil {
			return
			// todo: figure out a non noisy logging option here
			//  as this loop will be called very frequently
		}
	} else {
		if err := xdsutil.StructToMessage(filter.GetConfig(), hcm); err != nil {
			return
		}
	}
	httpFiltersRemoved := false
	for _, httpFilter := range hcm.HttpFilters {
		if httpFilter.Name == "" {
			continue
		}
		doHTTPFilterOperation(patchContext, patches, listener, fc, filter, httpFilter, &httpFiltersRemoved)
	}
	for _, cp := range patches[networking.EnvoyFilter_HTTP_FILTER] {
		if !patchContextMatch(patchContext, cp) ||
			!listenerMatch(patchContext, listener, cp) ||
			!filterChainMatch(fc, cp) ||
			!networkFilterMatch(filter, cp) {
			continue
		}

		if cp.Operation == networking.EnvoyFilter_Patch_ADD {
			hcm.HttpFilters = append(hcm.HttpFilters, cp.Value.(*http_conn.HttpFilter))
		} else if cp.Operation == networking.EnvoyFilter_Patch_INSERT_AFTER {
			hcm.HttpFilters = append(hcm.HttpFilters, cp.Value.(*http_conn.HttpFilter))
			for i := len(hcm.HttpFilters) - 2; i >= 1; i-- {
				if !httpFilterMatch(hcm.HttpFilters[i], cp) {
					hcm.HttpFilters[i-1], hcm.HttpFilters[i] = hcm.HttpFilters[i], hcm.HttpFilters[i-1]
				} else {
					break
				}
			}
		} else if cp.Operation == networking.EnvoyFilter_Patch_INSERT_BEFORE {
			hcm.HttpFilters = append(hcm.HttpFilters, cp.Value.(*http_conn.HttpFilter))
			for i := len(hcm.HttpFilters) - 2; i >= 1; i-- {
				match := httpFilterMatch(hcm.HttpFilters[i], cp)
				hcm.HttpFilters[i-1], hcm.HttpFilters[i] = hcm.HttpFilters[i], hcm.HttpFilters[i-1]
				if match {
					break
				}
			}
		}
	}
	if httpFiltersRemoved {
		tempArray := make([]*http_conn.HttpFilter, 0, len(hcm.HttpFilters))
		for _, filter := range hcm.HttpFilters {
			if filter.Name != "" {
				tempArray = append(tempArray, filter)
			}
		}
		hcm.HttpFilters = tempArray
	}
	if filter.GetTypedConfig() != nil {
		// convert to any type
		filter.ConfigType = &xdslistener.Filter_TypedConfig{TypedConfig: util.MessageToAny(hcm)}
	} else {
		filter.ConfigType = &xdslistener.Filter_Config{Config: util.MessageToStruct(hcm)}
	}
}

func doHTTPFilterOperation(patchContext networking.EnvoyFilter_PatchContext,
	patches map[networking.EnvoyFilter_ApplyTo][]*model.EnvoyFilterConfigPatchWrapper,
	listener *xdsapi.Listener, fc *xdslistener.FilterChain, filter *xdslistener.Filter,
	httpFilter *http_conn.HttpFilter, httpFilterRemoved *bool) {
	for _, cp := range patches[networking.EnvoyFilter_HTTP_FILTER] {
		if !patchContextMatch(patchContext, cp) ||
			!listenerMatch(patchContext, listener, cp) ||
			!filterChainMatch(fc, cp) ||
			!networkFilterMatch(filter, cp) ||
			!httpFilterMatch(httpFilter, cp) {
			continue
		}
		if cp.Operation == networking.EnvoyFilter_Patch_REMOVE {
			httpFilter.Name = ""
			*httpFilterRemoved = true
			// nothing more to do in other patches as we removed this filter
			return
		} else if cp.Operation == networking.EnvoyFilter_Patch_MERGE {
			proto.Merge(httpFilter, cp.Value)
		}
	}
}

func listenerMatch(_ networking.EnvoyFilter_PatchContext, listener *xdsapi.Listener,
	cp *model.EnvoyFilterConfigPatchWrapper) bool {
	cMatch := cp.Match.GetListener()
	if cMatch == nil {
		return true
	}

	// FIXME: Ports on a listener can be 0. the API only takes uint32 for ports
	// We should either make that field in API as a wrapper type or switch to int
	if cMatch.PortNumber != 0 {
		sockAddr := listener.Address.GetSocketAddress()
		if sockAddr == nil || sockAddr.GetPortValue() != cMatch.PortNumber {
			return false
		}
	}

	if cMatch.Name != "" && cMatch.Name != listener.Name {
		return false
	}

	return true
}

// We assume that the parent listener has already been matched
func filterChainMatch(fc *xdslistener.FilterChain, cp *model.EnvoyFilterConfigPatchWrapper) bool {
	cMatch := cp.Match.GetListener()
	if cMatch == nil {
		return true
	}

	match := cMatch.FilterChain
	if match == nil {
		return true
	}
	if match.Sni != "" {
		if fc.FilterChainMatch == nil || len(fc.FilterChainMatch.ServerNames) == 0 {
			return false
		}
		sniMatched := false
		for _, sni := range fc.FilterChainMatch.ServerNames {
			if sni == match.Sni {
				sniMatched = true
				break
			}
		}
		if !sniMatched {
			return false
		}
	}

	if match.TransportProtocol != "" {
		if fc.FilterChainMatch == nil || fc.FilterChainMatch.TransportProtocol != match.TransportProtocol {
			return false
		}
	}
	return true
}

// We assume that the parent listener and filter chain have already been matched
func networkFilterMatch(filter *xdslistener.Filter, cp *model.EnvoyFilterConfigPatchWrapper) bool {
	cMatch := cp.Match.GetListener()
	if cMatch == nil {
		return true
	}

	fcMatch := cMatch.FilterChain
	if fcMatch == nil {
		return true
	}

	match := fcMatch.Filter
	if match == nil {
		return true
	}

	return match.Name == filter.Name
}

// We assume that the parent listener and filter chain, and network filter have already been matched
func httpFilterMatch(filter *http_conn.HttpFilter, cp *model.EnvoyFilterConfigPatchWrapper) bool {
	cMatch := cp.Match.GetListener()
	if cMatch == nil {
		return true
	}

	fcMatch := cMatch.FilterChain
	if fcMatch == nil {
		return true
	}

	nMatch := fcMatch.Filter
	if nMatch == nil {
		return true
	}

	match := nMatch.SubFilter
	if match == nil {
		return true
	}

	return match.Name == filter.Name
}

func patchContextMatch(patchContext networking.EnvoyFilter_PatchContext,
	cp *model.EnvoyFilterConfigPatchWrapper) bool {
	return cp.Match.Context == patchContext || cp.Match.Context == networking.EnvoyFilter_ANY
}
