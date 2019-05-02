/*
Copyright The Kubernetes Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v1alpha1 "k8s.io/csi-api/pkg/apis/csi/v1alpha1"
)

// FakeCSINodeInfos implements CSINodeInfoInterface
type FakeCSINodeInfos struct {
	Fake *FakeCsiV1alpha1
}

var csinodeinfosResource = schema.GroupVersionResource{Group: "csi.storage.k8s.io", Version: "v1alpha1", Resource: "csinodeinfos"}

var csinodeinfosKind = schema.GroupVersionKind{Group: "csi.storage.k8s.io", Version: "v1alpha1", Kind: "CSINodeInfo"}

// Get takes name of the cSINodeInfo, and returns the corresponding cSINodeInfo object, and an error if there is any.
func (c *FakeCSINodeInfos) Get(name string, options v1.GetOptions) (result *v1alpha1.CSINodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(csinodeinfosResource, name), &v1alpha1.CSINodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CSINodeInfo), err
}

// List takes label and field selectors, and returns the list of CSINodeInfos that match those selectors.
func (c *FakeCSINodeInfos) List(opts v1.ListOptions) (result *v1alpha1.CSINodeInfoList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(csinodeinfosResource, csinodeinfosKind, opts), &v1alpha1.CSINodeInfoList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.CSINodeInfoList{ListMeta: obj.(*v1alpha1.CSINodeInfoList).ListMeta}
	for _, item := range obj.(*v1alpha1.CSINodeInfoList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested cSINodeInfos.
func (c *FakeCSINodeInfos) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(csinodeinfosResource, opts))
}

// Create takes the representation of a cSINodeInfo and creates it.  Returns the server's representation of the cSINodeInfo, and an error, if there is any.
func (c *FakeCSINodeInfos) Create(cSINodeInfo *v1alpha1.CSINodeInfo) (result *v1alpha1.CSINodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(csinodeinfosResource, cSINodeInfo), &v1alpha1.CSINodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CSINodeInfo), err
}

// Update takes the representation of a cSINodeInfo and updates it. Returns the server's representation of the cSINodeInfo, and an error, if there is any.
func (c *FakeCSINodeInfos) Update(cSINodeInfo *v1alpha1.CSINodeInfo) (result *v1alpha1.CSINodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(csinodeinfosResource, cSINodeInfo), &v1alpha1.CSINodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CSINodeInfo), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeCSINodeInfos) UpdateStatus(cSINodeInfo *v1alpha1.CSINodeInfo) (*v1alpha1.CSINodeInfo, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(csinodeinfosResource, "status", cSINodeInfo), &v1alpha1.CSINodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CSINodeInfo), err
}

// Delete takes name of the cSINodeInfo and deletes it. Returns an error if one occurs.
func (c *FakeCSINodeInfos) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(csinodeinfosResource, name), &v1alpha1.CSINodeInfo{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeCSINodeInfos) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(csinodeinfosResource, listOptions)

	_, err := c.Fake.Invokes(action, &v1alpha1.CSINodeInfoList{})
	return err
}

// Patch applies the patch and returns the patched cSINodeInfo.
func (c *FakeCSINodeInfos) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.CSINodeInfo, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(csinodeinfosResource, name, pt, data, subresources...), &v1alpha1.CSINodeInfo{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.CSINodeInfo), err
}
