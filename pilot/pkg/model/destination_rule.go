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

package model

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/visibility"
)

// This function merges one or more destination rules for a given host string
// into a single destination rule. Note that it does not perform inheritance style merging.
// IOW, given three dest rules (*.foo.com, *.foo.com, *.com), calling this function for
// each config will result in a final dest rule set (*.foo.com, and *.com).
//
// The following is the merge logic:
// 1. Unique subsets (based on subset name) are concatenated to the original rule's list of subsets
// 2. If the original rule did not have any top level traffic policy, traffic policies from the new rule will be
// used.
// 3. If the original rule did not have any exportTo, exportTo settings from the new rule will be used.
func (ps *PushContext) mergeDestinationRule(p *consolidatedDestRules, destRuleConfig config.Config, exportToMap map[visibility.Instance]bool) {
	rule := destRuleConfig.Spec.(*networking.DestinationRule)
	resolvedHost := ResolveShortnameToFQDN(rule.Host, destRuleConfig.Meta)
	if mdrList, exists := p.destRules[resolvedHost]; exists {
		// `addRuleToProcessedDestRules` determines if the incoming destination rule would become a new unique entry in the processedDestRules list.
		addRuleToProcessedDestRules := true
		for i, mdr := range mdrList {
			// Deep copy destination rule, to prevent mutate it later when merge with a new one.
			// This can happen when there are more than one destination rule of same host in one namespace.
			copied := mdr.DeepCopy()
			p.destRules[resolvedHost][i] = &copied
			mergedRule := copied.Spec.(*networking.DestinationRule)
			bothWithoutSelector := rule.GetWorkloadSelector() == nil && mergedRule.GetWorkloadSelector() == nil
			bothWithSelector := mergedRule.GetWorkloadSelector() != nil && rule.GetWorkloadSelector() != nil
			selectorsMatch := labels.Instance(mergedRule.GetWorkloadSelector().GetMatchLabels()).Equals(rule.GetWorkloadSelector().GetMatchLabels())

			if bothWithSelector && !selectorsMatch {
				// If the new destination rule and the existing one has workload selectors associated with them, skip merging
				// if the selectors do not match
				continue
			}

			// If both the destination rules are without a workload selector or with matching workload selectors, simply merge them.
			// If the incoming rule has a workload selector, it has to be merged with the existing rules with workload selector, and
			// at the same time added as a unique entry in the processedDestRules.
			if bothWithoutSelector || (rule.GetWorkloadSelector() != nil && selectorsMatch) {
				addRuleToProcessedDestRules = false
			}

			existingSubset := map[string]struct{}{}
			for _, subset := range mergedRule.Subsets {
				existingSubset[subset.Name] = struct{}{}
			}
			// we have an another destination rule for same host.
			// concatenate both of them -- essentially add subsets from one to other.
			// Note: we only add the subsets and do not overwrite anything else like exportTo or top level
			// traffic policies if they already exist
			for _, subset := range rule.Subsets {
				if _, ok := existingSubset[subset.Name]; !ok {
					// if not duplicated, append
					mergedRule.Subsets = append(mergedRule.Subsets, subset)
				} else {
					// duplicate subset
					ps.AddMetric(DuplicatedSubsets, string(resolvedHost), "",
						fmt.Sprintf("Duplicate subset %s found while merging destination rules for %s",
							subset.Name, string(resolvedHost)))
				}
			}

			// If there is no top level policy and the incoming rule has top level
			// traffic policy, use the one from the incoming rule.
			if mergedRule.TrafficPolicy == nil && rule.TrafficPolicy != nil {
				mergedRule.TrafficPolicy = rule.TrafficPolicy
			}
			// If there is no exportTo in the existing rule and
			// the incoming rule has an explicit exportTo, use the
			// one from the incoming rule.
			if len(p.exportTo[resolvedHost]) == 0 && len(exportToMap) > 0 {
				p.exportTo[resolvedHost] = exportToMap
			}
		}
		if addRuleToProcessedDestRules {
			p.destRules[resolvedHost] = append(p.destRules[resolvedHost], &destRuleConfig)
		}
		return
	}
	// DestinationRule does not exist for the resolved host so add it
	p.destRules[resolvedHost] = append(p.destRules[resolvedHost], &destRuleConfig)
	p.exportTo[resolvedHost] = exportToMap
}

// inheritDestinationRule child config inherits settings from parent mesh/namespace
func (ps *PushContext) inheritDestinationRule(parent, child *config.Config) *config.Config {
	if parent == nil {
		return child
	}
	if child == nil {
		return parent
	}

	parentDR := parent.Spec.(*networking.DestinationRule)
	if parentDR.TrafficPolicy == nil {
		return child
	}

	merged := parent.DeepCopy()
	// merge child into parent, child fields will overwrite parent's
	proto.Merge(merged.Spec.(proto.Message), child.Spec.(proto.Message))
	merged.Meta = child.Meta
	merged.Status = child.Status

	childDR := child.Spec.(*networking.DestinationRule)
	// if parent has MUTUAL+certs/secret specified and child specifies SIMPLE, could break caCertificates
	// if both parent and child specify TLS context, child's will be used only
	if parentDR.TrafficPolicy.Tls != nil && (childDR.TrafficPolicy != nil && childDR.TrafficPolicy.Tls != nil) {
		mergedDR := merged.Spec.(*networking.DestinationRule)
		mergedDR.TrafficPolicy.Tls = childDR.TrafficPolicy.Tls.DeepCopy()
	}

	return &merged
}
