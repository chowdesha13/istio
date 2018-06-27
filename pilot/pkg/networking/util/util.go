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

package util

import (
	base_json "encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	"github.com/envoyproxy/go-control-plane/pkg/util"
	"github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/log"
)

const (
	// BlackHoleCluster to catch traffic from routes with unresolved clusters. Traffic arriving here goes nowhere.
	BlackHoleCluster = "BlackHoleCluster"
)

//// convertAddressListToCidrList converts a list of IP addresses with cidr prefixes into envoy CIDR proto
//func convertAddressListToCidrList(addresses []string) []*core.CidrRange {
//	if addresses == nil {
//		return nil
//	}
//
//	cidrList := make([]*core.CidrRange, 0)
//	for _, addr := range addresses {
//		cidrList = append(cidrList, ConvertAddressToCidr(addr))
//	}
//	return cidrList
//}

// ALPNH2Only advertises that Proxy is going to use HTTP/2 when talking to the cluster.
var ALPNH2Only = []string{"h2"}

// ALPNInMeshH2 advertises that Proxy is going to use HTTP/2 when talking to the in-mesh cluster.
// The custom "istio" value indicates in-mesh traffic and it's going to be used for routing decisions.
// Once Envoy supports client-side ALPN negotiation, this should be {"istio", "h2", "http/1.1"}.
var ALPNInMeshH2 = []string{"istio", "h2"}

// ALPNInMesh advertises that Proxy is going to talk to the in-mesh cluster.
// The custom "istio" value indicates in-mesh traffic and it's going to be used for routing decisions.
var ALPNInMesh = []string{"istio"}

// ALPNHttp advertises that Proxy is going to talking either http2 or http 1.1.
var ALPNHttp = []string{"h2", "http/1.1"}

// ConvertAddressToCidr converts from string to CIDR proto
func ConvertAddressToCidr(addr string) *core.CidrRange {
	cidr := &core.CidrRange{
		AddressPrefix: addr,
		PrefixLen: &types.UInt32Value{
			Value: 32,
		},
	}

	if strings.Contains(addr, "/") {
		parts := strings.Split(addr, "/")
		cidr.AddressPrefix = parts[0]
		prefix, _ := strconv.Atoi(parts[1])
		cidr.PrefixLen.Value = uint32(prefix)
	}
	return cidr
}

// NormalizeListeners sorts and de-duplicates listeners by address
//func NormalizeListeners(listeners []*xdsapi.Listener) []*xdsapi.Listener {
//	out := make([]*xdsapi.Listener, 0, len(listeners))
//	set := make(map[string]bool)
//	for _, listener := range listeners {
//		if !set[listener.Address.String()] {
//			set[listener.Address.String()] = true
//			out = append(out, listener)
//		} else {
//			// we already have a listener on this address.
//			// WE can merge the two listeners if and only if they are of the same type
//			// i.e. both HTTP or both TCP.
//			// for the moment, we handle HTTP only. Need to do TCP. or use filter chain match
//			//existingListener := set[listener.Address.String()]
//			//if listener.ListenerFilters[0].
//		}
//	}
//	sort.Slice(out, func(i, j int) bool { return out[i].Address.String() < out[j].Address.String() })
//	return out
//}

// BuildAddress returns a SocketAddress with the given ip and port.
func BuildAddress(ip string, port uint32) core.Address {
	return core.Address{
		Address: &core.Address_SocketAddress{
			SocketAddress: &core.SocketAddress{
				Address: ip,
				PortSpecifier: &core.SocketAddress_PortValue{
					PortValue: port,
				},
			},
		},
	}
}

// BuildPipeAddress returns a Pipe address with the given path.
func BuildPipeAddress(path string) core.Address {
	return core.Address{Address: &core.Address_Pipe{Pipe: &core.Pipe{Path: path}}}
}

// GetNetworkEndpointAddress returns an Envoy v2 API `Address` that represents this NetworkEndpoint
func GetNetworkEndpointAddress(n *model.NetworkEndpoint) core.Address {
	switch n.Family {
	case model.AddressFamilyTCP:
		return BuildAddress(n.Address, uint32(n.Port))
	case model.AddressFamilyUnix:
		return BuildPipeAddress(n.Address)
	default:
		panic(fmt.Sprintf("unhandled Family %v", n.Family))
	}
}

// GetByAddress returns a listener by its address
// TODO(mostrowski): consider passing map around to save iteration.
func GetByAddress(listeners []*xdsapi.Listener, addr string) *xdsapi.Listener {
	for _, listener := range listeners {
		if listener != nil && listener.Address.String() == addr {
			return listener
		}
	}
	return nil
}

//// protoDurationToTimeDuration converts d to time.Duration format.
//func protoDurationToTimeDuration(d *types.Duration) time.Duration { //nolint
//	return time.Duration(d.Nanos) + time.Second*time.Duration(d.Seconds)
//}
//
//// google_protobufToProto converts d to google protobuf Duration format.
//func durationToProto(d time.Duration) *types.Duration { // nolint
//	nanos := d.Nanoseconds()
//	secs := nanos / 1e9
//	nanos -= secs * 1e9
//	return &types.Duration{
//		Seconds: secs,
//		Nanos:   int32(nanos),
//	}
//}

//func buildProtoStruct(name, value string) *types.Struct {
//	return &types.Struct{
//		Fields: map[string]*types.Value{
//			name: {
//				Kind: &types.Value_StringValue{
//					StringValue: value,
//				},
//			},
//		},
//	}
//}

// MessageToStruct converts from proto message to proto Struct
func MessageToStruct(msg proto.Message) *types.Struct {
	s, err := util.MessageToStruct(msg)
	if err != nil {
		log.Error(err.Error())
		return &types.Struct{}
	}
	return s
}

// GogoDurationToDuration converts from gogo proto duration to time.duration
func GogoDurationToDuration(d *types.Duration) time.Duration {
	if d == nil {
		return 0
	}
	dur, err := types.DurationFromProto(d)
	if err != nil {
		// TODO(mostrowski): add error handling instead.
		log.Warnf("error converting duration %#v, using 0: %v", d, err)
		return 0
	}
	return dur
}

// SortVirtualHosts sorts a slice of virtual hosts by name.
//
// Envoy computes a hash of the listener which is affected by order of elements in the filter. Therefore
// we sort virtual hosts by name before handing them back so the ordering is stable across HTTP Route Configs.
func SortVirtualHosts(hosts []route.VirtualHost) {
	sort.SliceStable(hosts, func(i, j int) bool {
		return hosts[i].Name < hosts[j].Name
	})
}

// PrettySprint pretty sprints v.
func PrettySprint(v interface{}) string {
	j, err := base_json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(j)
}
