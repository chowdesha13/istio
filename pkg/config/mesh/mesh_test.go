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

package mesh_test

import (
	"fmt"
	"reflect"
	"testing"

	. "github.com/onsi/gomega"

	meshconfig "istio.io/api/mesh/v1alpha1"

	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/validation"
)

func TestDefaultProxyConfig(t *testing.T) {
	proxyConfig := mesh.DefaultProxyConfig()
	if err := validation.ValidateProxyConfig(&proxyConfig); err != nil {
		t.Errorf("validation of default proxy config failed with %v", err)
	}
}

func TestDefaultMeshConfig(t *testing.T) {
	m := mesh.DefaultMeshConfig()
	if err := validation.ValidateMeshConfig(&m); err != nil {
		t.Errorf("validation of default mesh config failed with %v", err)
	}
}

func TestApplyMeshConfigDefaults(t *testing.T) {
	configPath := "/test/config/patch"
	yaml := fmt.Sprintf(`
defaultConfig:
  configPath: %s
`, configPath)

	want := mesh.DefaultMeshConfig()
	want.DefaultConfig.ConfigPath = configPath

	got, err := mesh.ApplyMeshConfigDefaults(yaml)
	if err != nil {
		t.Fatalf("ApplyMeshConfigDefaults() failed: %v", err)
	}
	if !reflect.DeepEqual(got, &want) {
		t.Fatalf("Wrong default values:\n got %#v \nwant %#v", got, &want)
	}
}

func TestApplyMeshNetworksDefaults(t *testing.T) {
	yml := fmt.Sprintf(`
networks:
  network1:
    endpoints:
    - fromCidr: "192.168.0.1/24"
    gateways:
    - address: 1.1.1.1
      port: 80
  network2:
    endpoints:
    - fromRegistry: reg1
    gateways:
    - registryServiceName: reg1
      port: 443
`)

	want := mesh.EmptyMeshNetworks()
	want.Networks = map[string]*meshconfig.Network{
		"network1": {
			Endpoints: []*meshconfig.Network_NetworkEndpoints{
				{
					Ne: &meshconfig.Network_NetworkEndpoints_FromCidr{
						FromCidr: "192.168.0.1/24",
					},
				},
			},
			Gateways: []*meshconfig.Network_IstioNetworkGateway{
				{
					Gw: &meshconfig.Network_IstioNetworkGateway_Address{
						Address: "1.1.1.1",
					},
					Port: 80,
				},
			},
		},
		"network2": {
			Endpoints: []*meshconfig.Network_NetworkEndpoints{
				{
					Ne: &meshconfig.Network_NetworkEndpoints_FromRegistry{
						FromRegistry: "reg1",
					},
				},
			},
			Gateways: []*meshconfig.Network_IstioNetworkGateway{
				{
					Gw: &meshconfig.Network_IstioNetworkGateway_RegistryServiceName{
						RegistryServiceName: "reg1",
					},
					Port: 443,
				},
			},
		},
	}

	got, err := mesh.ParseMeshNetworks(yml)
	if err != nil {
		t.Fatalf("ApplyMeshNetworksDefaults() failed: %v", err)
	}
	if !reflect.DeepEqual(got, &want) {
		t.Fatalf("Wrong values:\n got %#v \nwant %#v", got, &want)
	}
}

func TestResolveHostsInNetworksConfig(t *testing.T) {
	tests := []struct {
		name     string
		address  string
		modified bool
	}{
		{
			"Gateway with IP address",
			"9.142.3.1",
			false,
		},
		{
			"Gateway with localhost address",
			"localhost",
			true,
		},
		{
			"Gateway with empty address",
			"",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &meshconfig.MeshNetworks{
				Networks: map[string]*meshconfig.Network{
					"network": {
						Gateways: []*meshconfig.Network_IstioNetworkGateway{
							{
								Gw: &meshconfig.Network_IstioNetworkGateway_Address{
									Address: tt.address,
								},
							},
						},
					},
				},
			}
			mesh.ResolveHostsInNetworksConfig(config)
			addrAfter := config.Networks["network"].Gateways[0].GetAddress()
			if addrAfter == tt.address && tt.modified {
				t.Fatalf("Expected network address to be modified but it's the same as before calling the function")
			}
			if addrAfter != tt.address && !tt.modified {
				t.Fatalf("Expected network address not to be modified after calling the function")
			}
		})
	}
}

func TestIsClusterLocal(t *testing.T) {
	cases := []struct {
		name     string
		m        meshconfig.MeshConfig
		ns       string
		expected bool
	}{
		{
			name:     "local by default",
			m:        mesh.DefaultMeshConfig(),
			ns:       "kube-system",
			expected: true,
		},
		{
			name:     "not local by default",
			m:        mesh.DefaultMeshConfig(),
			ns:       "bob",
			expected: false,
		},
		{
			name: "local 1",
			m: meshconfig.MeshConfig{
				ClusterLocalNamespaces: []string{"ns1", "ns2"},
			},
			ns:       "ns1",
			expected: true,
		},
		{
			name: "local 2",
			m: meshconfig.MeshConfig{
				ClusterLocalNamespaces: []string{"ns1", "ns2"},
			},
			ns:       "ns2",
			expected: true,
		},
		{
			name: "not local",
			m: meshconfig.MeshConfig{
				ClusterLocalNamespaces: []string{"ns1", "ns2"},
			},
			ns:       "ns3",
			expected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := NewGomegaWithT(t)
			clusterLocal := mesh.IsClusterLocal(&c.m, c.ns)
			g.Expect(clusterLocal).To(Equal(c.expected))
		})
	}
}
