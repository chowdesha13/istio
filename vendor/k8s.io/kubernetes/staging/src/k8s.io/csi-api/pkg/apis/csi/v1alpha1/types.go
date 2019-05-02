/*
Copyright 2018 The Kubernetes Authors.

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

package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// VolumePluginMechanism is the type of mechanism components should use for volume operations
type VolumePluginMechanism string

const (
	// VolumePluginMechanismInTree means components should use the in-tree plugin for volume operations
	VolumePluginMechanismInTree VolumePluginMechanism = "in-tree"
	// VolumePluginMechanismCSI means components should use the CSI Driver for volume operations
	VolumePluginMechanismCSI VolumePluginMechanism = "csi"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CSIDriver captures information about a Container Storage Interface (CSI)
// volume driver deployed on the cluster.
// CSIDriver objects are non-namespaced.
type CSIDriver struct {
	metav1.TypeMeta `json:",inline"`

	// Standard object metadata.
	// metadata.Name indicates the name of the CSI driver that this object
	// refers to; it MUST be the same name returned by the CSI GetPluginName()
	// call for that driver.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Specification of the CSI Driver.
	Spec CSIDriverSpec `json:"spec"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CSIDriverList is a collection of CSIDriver objects.
type CSIDriverList struct {
	metav1.TypeMeta `json:",inline"`

	// Standard list metadata
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	// items is the list of CSIDriver
	Items []CSIDriver `json:"items"`
}

// CSIDriverSpec is the specification of a CSIDriver.
type CSIDriverSpec struct {
	// attachRequired indicates this CSI volume driver requires an attach
	// operation (because it implements the CSI ControllerPublishVolume()
	// method), and that Kubernetes should call attach and wait for any attach
	// operation to complete before proceeding to mounting.
	// If value is not specified, default is false -- meaning attach will not be
	// called.
	// +optional
	AttachRequired *bool `json:"attachRequired,omitempty"`

	// If specified, podInfoRequiredOnMount indicates this CSI volume driver
	// requires additional pod information (like podName, podUID, etc.) during
	// mount operations.
	// If value is not specified, pod information will not be passed on mount.
	// If value is set to a valid version, Kubelet will pass pod information as
	// VolumeAttributes in the CSI NodePublishVolume() calls.
	// Supported versions:
	// Version "v1" will pass the following ValueAttributes
	// "csi.storage.k8s.io/pod.name": pod.Name
	// "csi.storage.k8s.io/pod.namespace": pod.Namespace
	// "csi.storage.k8s.io/pod.uid": string(pod.UID)
	// +optional
	PodInfoOnMountVersion *string `json:"podInfoOnMountVersion,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CSINodeInfo holds information about all CSI drivers installed on a node.
type CSINodeInfo struct {
	metav1.TypeMeta `json:",inline"`

	// metadata.name must be the Kubernetes node name.
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec is the specification of CSINodeInfo
	Spec CSINodeInfoSpec `json:"spec"`

	// status is the current status of CSINodeInfo
	Status CSINodeInfoStatus `json:"status"`
}

// CSINodeInfoSpec holds information about the specification of all CSI drivers installed on a node
type CSINodeInfoSpec struct {
	// drivers is a list of specifications of CSIDriverInfo
	// +patchMergeKey=name
	// +patchStrategy=merge
	Drivers []CSIDriverInfoSpec `json:"drivers" patchStrategy:"merge" patchMergeKey:"name"`
}

// CSINodeInfoStatus holds information about the status of all CSI drivers installed on a node
type CSINodeInfoStatus struct {
	// drivers is a list of the statuses of CSIDriverInfo
	// +patchMergeKey=name
	// +patchStrategy=merge
	Drivers []CSIDriverInfoStatus `json:"drivers" patchStrategy:"merge" patchMergeKey:"name"`
}

// CSIDriverInfoStatus holds information about the status of one CSI driver installed on a node
type CSIDriverInfoStatus struct {
	// name is the name of the CSI driver that this object refers to.
	// This MUST be the same name returned by the CSI GetPluginName() call for
	// that driver.
	Name string `json:"name"`

	// available is a boolean representing whether the driver has been installed
	// on this node or not.
	Available bool `json:"available"`

	// volumePluginMechanism announces what mechanism underlies volume plugins.
	// It is set by Kubelet. It is used by the attach/detach controller, which
	// needs to know how to perform attachments. The allowed values are:
	// * "in-tree": the volume operation (e.g., attach/detach) ought to be
	//   directly performed by the attach/detach controller.
	// * "csi-plugin": the attach/detach controller ought to request
	//   the csi plugin to perform the volume operation rather than perform it directly.
	VolumePluginMechanism VolumePluginMechanism `json:"volumePluginMechanism"`
}

// CSIDriverInfoSpec holds information about the specification of one CSI driver installed on a node
type CSIDriverInfoSpec struct {
	// name is the name of the CSI driver that this object refers to.
	// This MUST be the same name returned by the CSI GetPluginName() call for
	// that driver.
	Name string `json:"name"`

	// nodeID of the node from the driver point of view.
	// This field enables Kubernetes to communicate with storage systems that do
	// not share the same nomenclature for nodes. For example, Kubernetes may
	// refer to a given node as "node1", but the storage system may refer to
	// the same node as "nodeA". When Kubernetes issues a command to the storage
	// system to attach a volume to a specific node, it can use this field to
	// refer to the node name using the ID that the storage system will
	// understand, e.g. "nodeA" instead of "node1".
	NodeID string `json:"nodeID"`

	// topologyKeys is the list of keys supported by the driver.
	// When a driver is initialized on a cluster, it provides a set of topology
	// keys that it understands (e.g. "company.com/zone", "company.com/region").
	// When a driver is initialized on a node it provides the same topology keys
	// along with values that kubelet applies to the coresponding node API
	// object as labels.
	// When Kubernetes does topology aware provisioning, it can use this list to
	// determine which labels it should retrieve from the node object and pass
	// back to the driver.
	TopologyKeys []string `json:"topologyKeys"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// CSINodeInfoList is a collection of CSINodeInfo objects.
type CSINodeInfoList struct {
	metav1.TypeMeta `json:",inline"`

	// Standard list metadata
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	// items is the list of CSINodeInfo
	Items []CSINodeInfo `json:"items"`
}
