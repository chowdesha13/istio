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

package v1alpha3_test

import (
	"fmt"
	"sort"
	"testing"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/networking/util"
	"istio.io/istio/pilot/pkg/simulation"
	"istio.io/istio/pilot/pkg/util/sets"
	"istio.io/istio/pilot/pkg/xds"
	"istio.io/istio/pkg/config/mesh"
)

func TestPassthroughTraffic(t *testing.T) {
	calls := map[string]simulation.Call{}
	for port := 80; port < 87; port++ {
		for _, call := range []simulation.Call{
			{Port: port, Protocol: simulation.HTTP, HostHeader: "foo"},
			{Port: port, Protocol: simulation.HTTPS, HostHeader: "foo"},
			{Port: port, Protocol: simulation.HTTPS, HostHeader: "foo", Alpn: "http/1.1"},
			{Port: port, Protocol: simulation.TCP, HostHeader: "foo"},
			{Port: port, Protocol: simulation.GRPC, HostHeader: "foo"},
		} {
			suffix := ""
			if call.Alpn != "" {
				suffix = "-" + call.Alpn
			}
			calls[fmt.Sprintf("%v-%v%v", call.Protocol, port, suffix)] = call
		}
	}
	ports := `
  ports:
  - name: http
    number: 80
    protocol: HTTP
  - name: auto
    number: 81
  - name: tcp
    number: 82
    protocol: TCP
  - name: tls
    number: 83
    protocol: TLS
  - name: https
    number: 84
    protocol: HTTPS
  - name: grpc
    number: 85
    protocol: GRPC
  - name: h2
    number: 86
    protocol: HTTP2`

	// TODO: https://github.com/istio/istio/issues/26079 this should be empty list
	expectedFailures := sets.NewSet(
		"https-80-http/1.1",
		"https-85-http/1.1",
		"https-86-http/1.1",
	)
	isHttpPort := func(p int) bool {
		switch p {
		case 80, 85, 86:
			return true
		default:
			return false
		}
	}
	isAutoPort := func(p int) bool {
		switch p {
		case 81:
			return true
		default:
			return false
		}
	}
	for _, tp := range []meshconfig.MeshConfig_OutboundTrafficPolicy_Mode{meshconfig.MeshConfig_OutboundTrafficPolicy_REGISTRY_ONLY, meshconfig.MeshConfig_OutboundTrafficPolicy_ALLOW_ANY} {
		t.Run(tp.String(), func(t *testing.T) {
			o := xds.FakeOptions{
				MeshConfig: func() *meshconfig.MeshConfig {
					m := mesh.DefaultMeshConfig()
					m.OutboundTrafficPolicy.Mode = tp
					return &m
				}(),
			}
			expectedCluster := map[meshconfig.MeshConfig_OutboundTrafficPolicy_Mode]string{
				meshconfig.MeshConfig_OutboundTrafficPolicy_REGISTRY_ONLY: util.BlackHoleCluster,
				meshconfig.MeshConfig_OutboundTrafficPolicy_ALLOW_ANY:     util.PassthroughCluster,
			}[tp]
			t.Run("with VIP", func(t *testing.T) {
				testCalls := []simulation.Expect{}
				for name, call := range calls {
					e := simulation.Expect{
						Name: name,
						Call: call,
						Result: simulation.Result{
							ClusterMatched: expectedCluster,
						},
					}
					// For blackhole, we will 502 where possible instead of blackhole cluster
					// This only works for HTTP on HTTP
					if expectedCluster == util.BlackHoleCluster && call.Protocol.IsHttp() && isHttpPort(call.Port) {
						e.Result.ClusterMatched = ""
						e.Result.VirtualHostMatched = util.BlackHole
					}
					if expectedFailures.Contains(name) {
						e.Result.Error = simulation.ErrProtocolError
						e.Result.ClusterMatched = ""
					}
					testCalls = append(testCalls, e)
				}
				sort.Slice(testCalls, func(i, j int) bool {
					return testCalls[i].Name < testCalls[j].Name
				})
				runSimulationTest(t, nil,
					simulationTest{
						config: `
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: se
spec:
  hosts:
  - istio.io
  addresses: [1.2.3.4]
  location: MESH_EXTERNAL
  resolution: DNS` + ports,
						calls: testCalls,
					}, o)
			})
			t.Run("without VIP", func(t *testing.T) {
				testCalls := []simulation.Expect{}
				for name, call := range calls {
					e := simulation.Expect{
						Name: name,
						Call: call,
						Result: simulation.Result{
							ClusterMatched: expectedCluster,
						},
					}
					// For blackhole, we will 502 where possible instead of blackhole cluster
					// This only works for HTTP on HTTP
					if expectedCluster == util.BlackHoleCluster && call.Protocol.IsHttp() && (isHttpPort(call.Port) || isAutoPort(call.Port)) {
						e.Result.ClusterMatched = ""
						e.Result.VirtualHostMatched = util.BlackHole
					}
					// TCP without a VIP will capture everything.
					// Auto without a VIP is similar, but HTTP happens to work because routing is done on header
					if call.Port == 82 || (call.Port == 81 && !call.Protocol.IsHttp()) {
						e.Result.Error = nil
						e.Result.ClusterMatched = ""
					}
					if expectedFailures.Contains(name) {
						e.Result.Error = simulation.ErrProtocolError
						e.Result.ClusterMatched = ""
					}
					testCalls = append(testCalls, e)
				}
				sort.Slice(testCalls, func(i, j int) bool {
					return testCalls[i].Name < testCalls[j].Name
				})
				runSimulationTest(t, nil,
					simulationTest{
						config: `
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: se
spec:
  hosts:
  - istio.io
  location: MESH_EXTERNAL
  resolution: DNS` + ports,
						calls: testCalls,
					}, o)
			})
		})
	}
}
