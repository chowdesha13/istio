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

package ambient

import (
	"fmt"
	"net/netip"
	"testing"

	v1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	meshapi "istio.io/api/mesh/v1alpha1"
	networking "istio.io/api/networking/v1alpha3"
	networkingclient "istio.io/client-go/pkg/apis/networking/v1alpha3"
	securityclient "istio.io/client-go/pkg/apis/security/v1beta1"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/network"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/workloadapi"
	"istio.io/istio/pkg/workloadapi/security"
)

func TestPodWorkloads(t *testing.T) {
	cases := []struct {
		name   string
		inputs []any
		pod    *v1.Pod
		result *workloadapi.Workload
	}{
		{
			name:   "simple pod not running and not have podIP",
			inputs: []any{},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
				Spec: v1.PodSpec{},
				Status: v1.PodStatus{
					Phase: v1.PodPending,
				},
			},
			result: nil,
		},
		{
			name:   "simple pod not running but have podIP",
			inputs: []any{},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
				Spec: v1.PodSpec{},
				Status: v1.PodStatus{
					Phase: v1.PodPending,
					PodIP: "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0//Pod/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "name",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_UNHEALTHY,
				ClusterId:         testC,
			},
		},
		{
			name:   "simple pod not ready",
			inputs: []any{},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
				Spec: v1.PodSpec{},
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					PodIP: "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0//Pod/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "name",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_UNHEALTHY,
				ClusterId:         testC,
			},
		},
		{
			name: "pod with service",
			inputs: []any{
				model.ServiceInfo{
					Service: &workloadapi.Service{
						Name:      "svc",
						Namespace: "ns",
						Hostname:  "hostname",
						Ports: []*workloadapi.Port{{
							ServicePort: 80,
							TargetPort:  8080,
						}},
					},
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
				},
			},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
					Labels: map[string]string{
						"app": "foo",
					},
				},
				Spec: v1.PodSpec{},
				Status: v1.PodStatus{
					Phase:      v1.PodRunning,
					Conditions: podReady,
					PodIP:      "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0//Pod/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "foo",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_HEALTHY,
				ClusterId:         testC,
				Services: map[string]*workloadapi.PortList{
					"ns/hostname": {
						Ports: []*workloadapi.Port{{
							ServicePort: 80,
							TargetPort:  8080,
						}},
					},
				},
			},
		},
		{
			name: "pod with service named ports",
			inputs: []any{
				model.ServiceInfo{
					Service: &workloadapi.Service{
						Name:      "svc",
						Namespace: "ns",
						Hostname:  "hostname",
						Ports: []*workloadapi.Port{
							{
								ServicePort: 80,
								TargetPort:  8080,
							},
							{
								ServicePort: 81,
								TargetPort:  0,
							},
							{
								ServicePort: 82,
								TargetPort:  0,
							},
						},
					},
					PortNames: map[int32]model.ServicePortName{
						// Not a named port
						80: {PortName: "80"},
						// Named port found in pod
						81: {PortName: "81", TargetPortName: "81-target"},
						// Named port not found in pod
						82: {PortName: "82", TargetPortName: "82-target"},
					},
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
				},
			},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
					Labels: map[string]string{
						"app": "foo",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{Ports: []v1.ContainerPort{
						{
							Name:          "81-target",
							ContainerPort: 9090,
							Protocol:      v1.ProtocolTCP,
						},
					}}},
				},
				Status: v1.PodStatus{
					Phase:      v1.PodRunning,
					Conditions: podReady,
					PodIP:      "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0//Pod/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "foo",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_HEALTHY,
				ClusterId:         testC,
				Services: map[string]*workloadapi.PortList{
					"ns/hostname": {
						Ports: []*workloadapi.Port{{
							ServicePort: 80,
							TargetPort:  8080,
						}, {
							ServicePort: 81,
							TargetPort:  9090,
						}},
					},
				},
			},
		},
		{
			name: "simple pod with locality",
			inputs: []any{
				&v1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: "node",
						Labels: map[string]string{
							v1.LabelTopologyRegion: "region",
							v1.LabelTopologyZone:   "zone",
						},
					},
				},
			},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
				},
				Spec: v1.PodSpec{NodeName: "node"},
				Status: v1.PodStatus{
					Phase: v1.PodPending,
					PodIP: "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0//Pod/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Node:              "node",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "name",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_UNHEALTHY,
				ClusterId:         testC,
				Locality: &workloadapi.Locality{
					Region: "region",
					Zone:   "zone",
				},
			},
		},
		{
			name: "pod with authz",
			inputs: []any{
				model.WorkloadAuthorization{
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
					Authorization: &security.Authorization{Name: "wrong-ns", Namespace: "not-ns"},
				},
				model.WorkloadAuthorization{
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
					Authorization: &security.Authorization{Name: "local-ns", Namespace: "ns"},
				},
				model.WorkloadAuthorization{
					LabelSelector: model.NewSelector(map[string]string{"app": "not-foo"}),
					Authorization: &security.Authorization{Name: "local-ns-wrong-labels", Namespace: "ns"},
				},
				model.WorkloadAuthorization{
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
					Authorization: &security.Authorization{Name: "root-ns", Namespace: "istio-system"},
				},
			},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
					Labels: map[string]string{
						"app": "foo",
					},
				},
				Spec: v1.PodSpec{},
				Status: v1.PodStatus{
					Phase:      v1.PodRunning,
					Conditions: podReady,
					PodIP:      "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0//Pod/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "foo",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_HEALTHY,
				ClusterId:         testC,
				AuthorizationPolicies: []string{
					"istio-system/root-ns",
					"ns/local-ns",
				},
			},
		},
		{
			name: "pod as part of selectorless service",
			inputs: []any{
				model.ServiceInfo{
					Service: &workloadapi.Service{
						Name:      "svc",
						Namespace: "default",
						Hostname:  "svc.default.svc.domain.suffix",
						Ports: []*workloadapi.Port{
							{
								ServicePort: 80,
								TargetPort:  80,
							},
						},
					},
					PortNames: map[int32]model.ServicePortName{
						80: {PortName: "80"},
					},
					// no selector!
					LabelSelector: model.LabelSelector{},
					Source:        kind.Service,
				},
				// EndpointSlice manually associates the pod with a service
				&discovery.EndpointSlice{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "svc-123",
						Namespace: "default",
						Labels: map[string]string{
							discovery.LabelServiceName: "svc",
						},
					},
					AddressType: discovery.AddressTypeIPv4,
					Endpoints: []discovery.Endpoint{
						{
							Addresses: []string{"1.2.3.4"},
							Conditions: discovery.EndpointConditions{
								Ready: ptr.Of(true),
							},
							TargetRef: &v1.ObjectReference{
								Kind:      "Pod",
								Name:      "pod-123",
								Namespace: "default",
							},
						},
					},
					Ports: []discovery.EndpointPort{
						{
							Name:     ptr.Of("http"),
							Protocol: ptr.Of(v1.ProtocolTCP),
							Port:     ptr.Of(int32(80)),
						},
					},
				},
			},
			pod: &v1.Pod{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pod-123",
					Namespace: "default",
					Labels: map[string]string{
						"app": "foo",
					},
				},
				Spec: v1.PodSpec{},
				Status: v1.PodStatus{
					Phase:      v1.PodRunning,
					Conditions: podReady,
					PodIP:      "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0//Pod/default/pod-123",
				Name:              "pod-123",
				Namespace:         "default",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "foo",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "pod-123",
				Status:            workloadapi.WorkloadStatus_HEALTHY,
				ClusterId:         testC,
				Services: map[string]*workloadapi.PortList{
					"default/svc.default.svc.domain.suffix": {
						Ports: []*workloadapi.Port{{
							ServicePort: 80,
							TargetPort:  80,
						}},
					},
				},
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			inputs := tt.inputs
			a := newAmbientUnitTest()
			AuthorizationPolicies := krt.NewStaticCollection(extractType[model.WorkloadAuthorization](&inputs))
			PeerAuths := krt.NewStaticCollection(extractType[*securityclient.PeerAuthentication](&inputs))
			Waypoints := krt.NewStaticCollection(extractType[Waypoint](&inputs))
			WorkloadServices := krt.NewStaticCollection(extractType[model.ServiceInfo](&inputs))
			m := slices.First(extractType[meshapi.MeshConfig](&inputs))
			if m == nil {
				m = mesh.DefaultMeshConfig()
			}
			MeshConfig := krt.NewStatic(&MeshConfig{m})
			Namespaces := krt.NewStaticCollection(extractType[*v1.Namespace](&inputs))
			Nodes := krt.NewStaticCollection(extractType[*v1.Node](&inputs))
			EndpointSlices := krt.NewStaticCollection(extractType[*discovery.EndpointSlice](&inputs))
			assert.Equal(t, len(inputs), 0, fmt.Sprintf("some inputs were not consumed: %v", inputs))
			WorkloadServicesNamespaceIndex := krt.NewNamespaceIndex(WorkloadServices)
			EndpointSlicesAddressIndex := endpointSliceAddressIndex(EndpointSlices)
			builder := a.podWorkloadBuilder(
				MeshConfig,
				AuthorizationPolicies,
				PeerAuths,
				Waypoints,
				WorkloadServices,
				WorkloadServicesNamespaceIndex,
				EndpointSlices,
				EndpointSlicesAddressIndex,
				Namespaces,
				Nodes,
			)
			wrapper := builder(krt.TestingDummyContext{}, tt.pod)
			var res *workloadapi.Workload
			if wrapper != nil {
				res = wrapper.Workload
			}
			assert.Equal(t, res, tt.result)
		})
	}
}

func TestWorkloadEntryWorkloads(t *testing.T) {
	cases := []struct {
		name   string
		inputs []any
		we     *networkingclient.WorkloadEntry
		result *workloadapi.Workload
	}{
		{
			name: "we with service",
			inputs: []any{
				model.ServiceInfo{
					Service: &workloadapi.Service{
						Name:      "svc",
						Namespace: "ns",
						Hostname:  "hostname",
						Ports: []*workloadapi.Port{{
							ServicePort: 80,
							TargetPort:  8080,
						}},
					},
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
				},
			},
			we: &networkingclient.WorkloadEntry{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
					Labels: map[string]string{
						"app": "foo",
					},
				},
				Spec: networking.WorkloadEntry{
					Address: "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0/networking.istio.io/WorkloadEntry/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "foo",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_HEALTHY,
				ClusterId:         testC,
				Services: map[string]*workloadapi.PortList{
					"ns/hostname": {
						Ports: []*workloadapi.Port{{
							ServicePort: 80,
							TargetPort:  8080,
						}},
					},
				},
			},
		},
		{
			name: "pod with service named ports",
			inputs: []any{
				model.ServiceInfo{
					Service: &workloadapi.Service{
						Name:      "svc",
						Namespace: "ns",
						Hostname:  "hostname",
						Ports: []*workloadapi.Port{
							{
								ServicePort: 80,
								TargetPort:  8080,
							},
							{
								ServicePort: 81,
								TargetPort:  0,
							},
							{
								ServicePort: 82,
								TargetPort:  0,
							},
							{
								ServicePort: 83,
								TargetPort:  0,
							},
						},
					},
					PortNames: map[int32]model.ServicePortName{
						// Not a named port
						80: {PortName: "80"},
						// Named port found in WE
						81: {PortName: "81", TargetPortName: "81-target"},
						// Named port target found in WE
						82: {PortName: "82", TargetPortName: "82-target"},
						// Named port not found in WE
						83: {PortName: "83", TargetPortName: "83-target"},
					},
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
					Source:        kind.Service,
				},
			},
			we: &networkingclient.WorkloadEntry{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
					Labels: map[string]string{
						"app": "foo",
					},
				},
				Spec: networking.WorkloadEntry{
					Ports: map[string]uint32{
						"81":        8180,
						"82-target": 8280,
					},
					Address: "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0/networking.istio.io/WorkloadEntry/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "foo",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_HEALTHY,
				ClusterId:         testC,
				Services: map[string]*workloadapi.PortList{
					"ns/hostname": {
						Ports: []*workloadapi.Port{
							{
								ServicePort: 80,
								TargetPort:  8080,
							},
							{
								ServicePort: 82,
								TargetPort:  8280,
							},
						},
					},
				},
			},
		},
		{
			name: "pod with serviceentry named ports",
			inputs: []any{
				model.ServiceInfo{
					Service: &workloadapi.Service{
						Name:      "svc",
						Namespace: "ns",
						Hostname:  "hostname",
						Ports: []*workloadapi.Port{
							{
								ServicePort: 80,
								TargetPort:  8080,
							},
							{
								ServicePort: 81,
								TargetPort:  0,
							},
							{
								ServicePort: 82,
								TargetPort:  0,
							},
						},
					},
					PortNames: map[int32]model.ServicePortName{
						// TargetPort explicitly set
						80: {PortName: "80"},
						// Port name found
						81: {PortName: "81"},
						// Port name not found
						82: {PortName: "82"},
					},
					LabelSelector: model.NewSelector(map[string]string{"app": "foo"}),
					Source:        kind.ServiceEntry,
				},
			},
			we: &networkingclient.WorkloadEntry{
				TypeMeta: metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "ns",
					Labels: map[string]string{
						"app": "foo",
					},
				},
				Spec: networking.WorkloadEntry{
					Ports: map[string]uint32{
						"81": 8180,
					},
					Address: "1.2.3.4",
				},
			},
			result: &workloadapi.Workload{
				Uid:               "cluster0/networking.istio.io/WorkloadEntry/ns/name",
				Name:              "name",
				Namespace:         "ns",
				Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
				Network:           testNW,
				CanonicalName:     "foo",
				CanonicalRevision: "latest",
				WorkloadType:      workloadapi.WorkloadType_POD,
				WorkloadName:      "name",
				Status:            workloadapi.WorkloadStatus_HEALTHY,
				ClusterId:         testC,
				Services: map[string]*workloadapi.PortList{
					"ns/hostname": {
						Ports: []*workloadapi.Port{
							{
								ServicePort: 80,
								TargetPort:  8080,
							},
							{
								ServicePort: 81,
								TargetPort:  8180,
							},
							{
								ServicePort: 82,
								TargetPort:  82,
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			inputs := tt.inputs
			a := newAmbientUnitTest()
			AuthorizationPolicies := krt.NewStaticCollection(extractType[model.WorkloadAuthorization](&inputs))
			PeerAuths := krt.NewStaticCollection(extractType[*securityclient.PeerAuthentication](&inputs))
			Waypoints := krt.NewStaticCollection(extractType[Waypoint](&inputs))
			WorkloadServices := krt.NewStaticCollection(extractType[model.ServiceInfo](&inputs))
			Namespaces := krt.NewStaticCollection(extractType[*v1.Namespace](&inputs))
			MeshConfig := krt.NewStatic(&MeshConfig{slices.First(extractType[meshapi.MeshConfig](&inputs))})
			assert.Equal(t, len(inputs), 0, fmt.Sprintf("some inputs were not consumed: %v", inputs))
			WorkloadServicesNamespaceIndex := krt.NewNamespaceIndex(WorkloadServices)
			builder := a.workloadEntryWorkloadBuilder(
				MeshConfig,
				AuthorizationPolicies,
				PeerAuths,
				Waypoints,
				WorkloadServices,
				WorkloadServicesNamespaceIndex,
				Namespaces,
			)
			wrapper := builder(krt.TestingDummyContext{}, tt.we)
			var res *workloadapi.Workload
			if wrapper != nil {
				res = wrapper.Workload
			}
			assert.Equal(t, res, tt.result)
		})
	}
}

func TestEndpointSliceWorkloads(t *testing.T) {
	cases := []struct {
		name   string
		inputs []any
		slice  *discovery.EndpointSlice
		result []*workloadapi.Workload
	}{
		{
			name:   "api server",
			inputs: []any{},
			slice: &discovery.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "kubernetes",
					Namespace: "default",
					Labels: map[string]string{
						discovery.LabelServiceName: "kubernetes",
					},
				},
				AddressType: discovery.AddressTypeIPv4,
				Endpoints: []discovery.Endpoint{
					{
						Addresses: []string{"172.18.0.5"},
						Conditions: discovery.EndpointConditions{
							Ready: ptr.Of(true),
						},
					},
				},
				Ports: []discovery.EndpointPort{
					{
						Name:     ptr.Of("https"),
						Protocol: ptr.Of(v1.ProtocolTCP),
						Port:     ptr.Of(int32(6443)),
					},
				},
			},
			result: nil,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			inputs := tt.inputs
			a := newAmbientUnitTest()
			WorkloadServices := krt.NewStaticCollection(extractType[model.ServiceInfo](&inputs))
			m := slices.First(extractType[meshapi.MeshConfig](&inputs))
			if m == nil {
				m = mesh.DefaultMeshConfig()
			}
			MeshConfig := krt.NewStatic(&MeshConfig{m})
			builder := a.endpointSlicesBuilder(
				MeshConfig,
				WorkloadServices,
			)
			res := builder(krt.TestingDummyContext{}, tt.slice)
			wl := slices.Map(res, func(e model.WorkloadInfo) *workloadapi.Workload {
				return e.Workload
			})
			assert.Equal(t, wl, tt.result)
		})
	}
}

func newAmbientUnitTest() *index {
	return &index{
		networkUpdateTrigger: krt.NewRecomputeTrigger(),
		ClusterID:            testC,
		Network: func(endpointIP string, labels labels.Instance) network.ID {
			return testNW
		},
		DomainSuffix: "domain.suffix",
	}
}

func extractType[T any](items *[]any) []T {
	var matched []T
	var unmatched []any
	arr := *items
	for _, val := range arr {
		if c, ok := val.(T); ok {
			matched = append(matched, c)
		} else {
			unmatched = append(unmatched, val)
		}
	}

	*items = unmatched
	return matched
}

var podReady = []v1.PodCondition{
	{
		Type:               v1.PodReady,
		Status:             v1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
	},
}
