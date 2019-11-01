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
package sidecar

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"

	"istio.io/api/networking/v1alpha3"
	"istio.io/istio/galley/pkg/config/analysis"
	"istio.io/istio/galley/pkg/config/analysis/msg"
	"istio.io/istio/galley/pkg/config/meta/metadata"
	"istio.io/istio/galley/pkg/config/meta/schema/collection"
	"istio.io/istio/galley/pkg/config/resource"
)

// OverlapSelectorAnalyzer validates, per namespace, that there aren't multiple Sidecar resources that
// select overlapping service workloads
// Also checks for Sidecars with no matching pods at all, despite defining a workload selector.
type OverlapSelectorAnalyzer struct{}

var _ analysis.Analyzer = &OverlapSelectorAnalyzer{}

// Metadata implements Analyzer
func (a *OverlapSelectorAnalyzer) Metadata() analysis.Metadata {
	return analysis.Metadata{
		Name: "sidecar.OverlapSelectorAnalyzer",
		Inputs: collection.Names{
			metadata.IstioNetworkingV1Alpha3Sidecars,
			metadata.K8SCoreV1Pods,
		},
	}
}

// Analyze implements Analyzer
func (a *OverlapSelectorAnalyzer) Analyze(c analysis.Context) {
	//TODO: Check for overlapping workload selectors?

	podsToSidecars := make(map[resource.Name][]*resource.Entry)

	// This is using an unindexed approach for selectors.
	// Using an index for selectoes is problematic because selector != label
	// and we can't know ahead of time what will match a label
	c.ForEach(metadata.IstioNetworkingV1Alpha3Sidecars, func(rs *resource.Entry) bool {
		s := rs.Item.(*v1alpha3.Sidecar)

		// For this analysis, ignore Sidecars with no workload selectors specified at all.
		if s.WorkloadSelector == nil || len(s.WorkloadSelector.Labels) == 0 {
			return true
		}

		sNs, _ := rs.Metadata.Name.InterpretAsNamespaceAndName()
		sel := labels.SelectorFromSet(s.WorkloadSelector.Labels)

		foundPod := false
		c.ForEach(metadata.K8SCoreV1Pods, func(rp *resource.Entry) bool {
			pod := rp.Item.(*v1.Pod)
			pNs, _ := rp.Metadata.Name.InterpretAsNamespaceAndName()
			podLabels := labels.Set(pod.ObjectMeta.Labels)

			// Only attempt to match in the same namespace
			if pNs != sNs {
				return true
			}

			if sel.Matches(podLabels) {
				foundPod = true
				podsToSidecars[rp.Metadata.Name] = append(podsToSidecars[rp.Metadata.Name], rs)
			}

			return true
		})

		if !foundPod {
			c.Report(metadata.IstioNetworkingV1Alpha3Sidecars, msg.NewReferencedResourceNotFound(rs, "selector", sel.String()))
		}

		return true
	})

	for p, rsList := range podsToSidecars {
		if len(rsList) == 1 {
			continue
		}
		for _, rs := range rsList {
			//TODO: New message type
			c.Report(metadata.IstioNetworkingV1Alpha3Sidecars, msg.NewInternalError(rs,
				fmt.Sprintf("The Sidecars %v select the same workload pod %q, which can lead to undefined behavior.", rsList, p)))

		}
	}
}
