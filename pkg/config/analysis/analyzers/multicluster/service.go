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

package multicluster

import (
	"reflect"
	"sort"

	corev1 "k8s.io/api/core/v1"

	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/analysis"
	"istio.io/istio/pkg/config/analysis/msg"
	"istio.io/istio/pkg/config/resource"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

// ServiceAnalyzer validates services in multi-cluster.
type ServiceAnalyzer struct{}

var _ analysis.Analyzer = &ServiceAnalyzer{}

// Metadata implements Analyzer
func (s *ServiceAnalyzer) Metadata() analysis.Metadata {
	return analysis.Metadata{
		Name:        "services.MultiClusterServiceAnalyzer",
		Description: "Check the validity of services in the multi-cluster environment",
		Inputs: []config.GroupVersionKind{
			gvk.Service,
		},
	}
}

// clusterService holds details about a service instance in a cluster.
type clusterService struct {
	clusterID cluster.ID
	instance  *resource.Instance
}

// Analyze implements Analyzer
func (s *ServiceAnalyzer) Analyze(c analysis.Context) {
	services := map[resource.FullName][]*clusterService{}
	c.ForEach(gvk.Service, func(r *resource.Instance) bool {
		clusterID := r.Origin.ClusterName()
		if clusterID == "" {
			return true
		}
		if _, ok := services[r.Metadata.FullName]; !ok {
			services[r.Metadata.FullName] = []*clusterService{}
		}
		services[r.Metadata.FullName] = append(services[r.Metadata.FullName], &clusterService{
			clusterID: clusterID,
			instance:  r,
		})
		return true
	})

	for fullname, clusterServices := range services {
		if len(clusterServices) == 1 {
			continue
		}
		inconsistents, errors := findInconsistencies(clusterServices)
		if len(inconsistents) > 0 {
			var serviceInstance *resource.Instance
			for _, svc := range clusterServices {
				if svc != nil {
					serviceInstance = svc.instance
					break
				}
			}
			message := msg.NewMultiClusterInconsistentService(serviceInstance, fullname.Name.String(),
				fullname.Namespace.String(), inconsistents, errors)

			c.Report(gvk.Service, message)
		}
	}
}

func findInconsistencies(services []*clusterService) (clusters []string, errors string) {
	inconsistentClusters := sets.New[string]()
	inconsistentReasons := sets.New[string]()

	// Convert the first service from resource.Instance to corev1.Service
	var firstService *corev1.ServiceSpec
	var firstClusterID cluster.ID
	for _, svc := range services {
		firstClusterID = svc.clusterID
		firstService = svc.instance.Message.(*corev1.ServiceSpec)
		if firstService != nil {
			break
		}
	}

	var addedHeadless bool
	for _, svc := range services {
		service := svc.instance.Message.(*corev1.ServiceSpec)

		// Compare if service has mixed mode like headless and clusterIP
		if !addedHeadless && (firstService.ClusterIP == corev1.ClusterIPNone) != (service.ClusterIP == corev1.ClusterIPNone) {
			addedHeadless = true
			for _, s := range services {
				inconsistentClusters.Insert(s.clusterID.String())
			}
			inconsistentReasons.Insert("service has mixed mode like headless and clusterIP")
		}

		// Compare service types
		if firstService.Type != service.Type {
			inconsistentClusters.Insert(svc.clusterID.String())
			inconsistentReasons.Insert("service type is inconsistent")
		}

		// Compare ports
		if !compareServicePorts(firstService.Ports, service.Ports) {
			inconsistentClusters.Insert(svc.clusterID.String())
			inconsistentReasons.Insert("service ports are inconsistent")
		}
	}
	if len(inconsistentClusters) > 0 {
		inconsistentClusters.Insert(firstClusterID.String())
	}
	slices.Sort(inconsistentReasons.UnsortedList())
	errStr := ""
	for i, err := range inconsistentReasons.UnsortedList() {
		errStr += err
		if i < len(inconsistentReasons)-1 {
			errStr += "; "
		}
	}
	return inconsistentClusters.UnsortedList(), errStr
}

func compareServicePorts(a, b []corev1.ServicePort) bool {
	if len(a) != len(b) {
		return false
	}

	sort.SliceStable(a, func(i, j int) bool {
		return a[i].Name < a[j].Name
	})

	sort.SliceStable(b, func(i, j int) bool {
		return b[i].Name < b[j].Name
	})
	return reflect.DeepEqual(a, b)
}
