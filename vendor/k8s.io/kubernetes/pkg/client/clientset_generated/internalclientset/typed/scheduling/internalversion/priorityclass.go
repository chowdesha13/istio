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

package internalversion

import (
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	scheduling "k8s.io/kubernetes/pkg/apis/scheduling"
	scheme "k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/scheme"
)

// PriorityClassesGetter has a method to return a PriorityClassInterface.
// A group's client should implement this interface.
type PriorityClassesGetter interface {
	PriorityClasses() PriorityClassInterface
}

// PriorityClassInterface has methods to work with PriorityClass resources.
type PriorityClassInterface interface {
	Create(*scheduling.PriorityClass) (*scheduling.PriorityClass, error)
	Update(*scheduling.PriorityClass) (*scheduling.PriorityClass, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*scheduling.PriorityClass, error)
	List(opts v1.ListOptions) (*scheduling.PriorityClassList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *scheduling.PriorityClass, err error)
	PriorityClassExpansion
}

// priorityClasses implements PriorityClassInterface
type priorityClasses struct {
	client rest.Interface
}

// newPriorityClasses returns a PriorityClasses
func newPriorityClasses(c *SchedulingClient) *priorityClasses {
	return &priorityClasses{
		client: c.RESTClient(),
	}
}

// Get takes name of the priorityClass, and returns the corresponding priorityClass object, and an error if there is any.
func (c *priorityClasses) Get(name string, options v1.GetOptions) (result *scheduling.PriorityClass, err error) {
	result = &scheduling.PriorityClass{}
	err = c.client.Get().
		Resource("priorityclasses").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of PriorityClasses that match those selectors.
func (c *priorityClasses) List(opts v1.ListOptions) (result *scheduling.PriorityClassList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &scheduling.PriorityClassList{}
	err = c.client.Get().
		Resource("priorityclasses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested priorityClasses.
func (c *priorityClasses) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("priorityclasses").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a priorityClass and creates it.  Returns the server's representation of the priorityClass, and an error, if there is any.
func (c *priorityClasses) Create(priorityClass *scheduling.PriorityClass) (result *scheduling.PriorityClass, err error) {
	result = &scheduling.PriorityClass{}
	err = c.client.Post().
		Resource("priorityclasses").
		Body(priorityClass).
		Do().
		Into(result)
	return
}

// Update takes the representation of a priorityClass and updates it. Returns the server's representation of the priorityClass, and an error, if there is any.
func (c *priorityClasses) Update(priorityClass *scheduling.PriorityClass) (result *scheduling.PriorityClass, err error) {
	result = &scheduling.PriorityClass{}
	err = c.client.Put().
		Resource("priorityclasses").
		Name(priorityClass.Name).
		Body(priorityClass).
		Do().
		Into(result)
	return
}

// Delete takes name of the priorityClass and deletes it. Returns an error if one occurs.
func (c *priorityClasses) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("priorityclasses").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *priorityClasses) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("priorityclasses").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched priorityClass.
func (c *priorityClasses) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *scheduling.PriorityClass, err error) {
	result = &scheduling.PriorityClass{}
	err = c.client.Patch(pt).
		Resource("priorityclasses").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
