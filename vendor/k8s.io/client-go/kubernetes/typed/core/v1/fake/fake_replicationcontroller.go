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
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeReplicationControllers implements ReplicationControllerInterface
type FakeReplicationControllers struct {
	Fake *FakeCoreV1
	ns   string
}

var replicationcontrollersResource = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "replicationcontrollers"}

var replicationcontrollersKind = schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ReplicationController"}

// Get takes name of the replicationController, and returns the corresponding replicationController object, and an error if there is any.
func (c *FakeReplicationControllers) Get(name string, options v1.GetOptions) (result *corev1.ReplicationController, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetAction(replicationcontrollersResource, c.ns, name), &corev1.ReplicationController{})

	if obj == nil {
		return nil, err
	}
	return obj.(*corev1.ReplicationController), err
}

// List takes label and field selectors, and returns the list of ReplicationControllers that match those selectors.
func (c *FakeReplicationControllers) List(opts v1.ListOptions) (result *corev1.ReplicationControllerList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewListAction(replicationcontrollersResource, replicationcontrollersKind, c.ns, opts), &corev1.ReplicationControllerList{})

	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &corev1.ReplicationControllerList{ListMeta: obj.(*corev1.ReplicationControllerList).ListMeta}
	for _, item := range obj.(*corev1.ReplicationControllerList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested replicationControllers.
func (c *FakeReplicationControllers) Watch(opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewWatchAction(replicationcontrollersResource, c.ns, opts))

}

// Create takes the representation of a replicationController and creates it.  Returns the server's representation of the replicationController, and an error, if there is any.
func (c *FakeReplicationControllers) Create(replicationController *corev1.ReplicationController) (result *corev1.ReplicationController, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewCreateAction(replicationcontrollersResource, c.ns, replicationController), &corev1.ReplicationController{})

	if obj == nil {
		return nil, err
	}
	return obj.(*corev1.ReplicationController), err
}

// Update takes the representation of a replicationController and updates it. Returns the server's representation of the replicationController, and an error, if there is any.
func (c *FakeReplicationControllers) Update(replicationController *corev1.ReplicationController) (result *corev1.ReplicationController, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateAction(replicationcontrollersResource, c.ns, replicationController), &corev1.ReplicationController{})

	if obj == nil {
		return nil, err
	}
	return obj.(*corev1.ReplicationController), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeReplicationControllers) UpdateStatus(replicationController *corev1.ReplicationController) (*corev1.ReplicationController, error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(replicationcontrollersResource, "status", c.ns, replicationController), &corev1.ReplicationController{})

	if obj == nil {
		return nil, err
	}
	return obj.(*corev1.ReplicationController), err
}

// Delete takes name of the replicationController and deletes it. Returns an error if one occurs.
func (c *FakeReplicationControllers) Delete(name string, options *v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewDeleteAction(replicationcontrollersResource, c.ns, name), &corev1.ReplicationController{})

	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeReplicationControllers) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	action := testing.NewDeleteCollectionAction(replicationcontrollersResource, c.ns, listOptions)

	_, err := c.Fake.Invokes(action, &corev1.ReplicationControllerList{})
	return err
}

// Patch applies the patch and returns the patched replicationController.
func (c *FakeReplicationControllers) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *corev1.ReplicationController, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewPatchSubresourceAction(replicationcontrollersResource, c.ns, name, pt, data, subresources...), &corev1.ReplicationController{})

	if obj == nil {
		return nil, err
	}
	return obj.(*corev1.ReplicationController), err
}

// GetScale takes name of the replicationController, and returns the corresponding scale object, and an error if there is any.
func (c *FakeReplicationControllers) GetScale(replicationControllerName string, options v1.GetOptions) (result *autoscalingv1.Scale, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewGetSubresourceAction(replicationcontrollersResource, c.ns, "scale", replicationControllerName), &autoscalingv1.Scale{})

	if obj == nil {
		return nil, err
	}
	return obj.(*autoscalingv1.Scale), err
}

// UpdateScale takes the representation of a scale and updates it. Returns the server's representation of the scale, and an error, if there is any.
func (c *FakeReplicationControllers) UpdateScale(replicationControllerName string, scale *autoscalingv1.Scale) (result *autoscalingv1.Scale, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewUpdateSubresourceAction(replicationcontrollersResource, "scale", c.ns, scale), &autoscalingv1.Scale{})

	if obj == nil {
		return nil, err
	}
	return obj.(*autoscalingv1.Scale), err
}
