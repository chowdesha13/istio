/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package markcontrolplane

import (
	"fmt"

	"k8s.io/api/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/cmd/kubeadm/app/constants"
	"k8s.io/kubernetes/cmd/kubeadm/app/util/apiclient"
)

// MarkControlPlane taints the control-plane and sets the control-plane label
func MarkControlPlane(client clientset.Interface, controlPlaneName string, taints []v1.Taint) error {

	fmt.Printf("[mark-control-plane] Marking the node %s as control-plane by adding the label \"%s=''\"\n", controlPlaneName, constants.LabelNodeRoleMaster)

	if taints != nil && len(taints) > 0 {
		taintStrs := []string{}
		for _, taint := range taints {
			taintStrs = append(taintStrs, taint.ToString())
		}
		fmt.Printf("[mark-control-plane] Marking the node %s as control-plane by adding the taints %v\n", controlPlaneName, taintStrs)
	}

	return apiclient.PatchNode(client, controlPlaneName, func(n *v1.Node) {
		markMasterNode(n, taints)
	})
}

func taintExists(taint v1.Taint, taints []v1.Taint) bool {
	for _, t := range taints {
		if t == taint {
			return true
		}
	}

	return false
}

func markMasterNode(n *v1.Node, taints []v1.Taint) {
	n.ObjectMeta.Labels[constants.LabelNodeRoleMaster] = ""

	for _, nt := range n.Spec.Taints {
		if !taintExists(nt, taints) {
			taints = append(taints, nt)
		}
	}

	n.Spec.Taints = taints
}
