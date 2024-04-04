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

package kubeclient

import (
	"context"

	kubeext "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/tools/cache"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	istioclient "istio.io/client-go/pkg/clientset/versioned"
	"istio.io/istio/pilot/pkg/util/informermetric"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/kubetypes"
	"istio.io/istio/pkg/kube/informerfactory"
	ktypes "istio.io/istio/pkg/kube/kubetypes"
	"istio.io/istio/pkg/log"
)

type ClientGetter interface {
	// Ext returns the API extensions client.
	Ext() kubeext.Interface

	// Kube returns the core kube client
	Kube() kubernetes.Interface

	// Dynamic client.
	Dynamic() dynamic.Interface

	// Metadata returns the Metadata kube client.
	Metadata() metadata.Interface

	// Istio returns the Istio kube client.
	Istio() istioclient.Interface

	// GatewayAPI returns the gateway-api kube client.
	GatewayAPI() gatewayapiclient.Interface

	// Informers returns an informer factory.
	Informers() informerfactory.InformerFactory
}

func GetInformerFiltered[T runtime.Object](c ClientGetter, opts ktypes.InformerOptions) informerfactory.StartableInformer {
	for _, reg := range registerType {
		if tr, ok := reg.(TypeRegistration[T]); ok {
			return c.Informers().InformerFor(tr.GetGVR(), opts, func() cache.SharedIndexInformer {
				inf := cache.NewSharedIndexInformer(
					tr.ListWatch(c, opts),
					tr.Object(),
					0,
					cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				)
				setupInformer(opts, inf)
				return inf
			})
		}
	}
	return GetInformerFilteredFromGVR(c, opts, kubetypes.GetGVR[T]())
}

func GetInformerFilteredFromGVR(c ClientGetter, opts ktypes.InformerOptions, g schema.GroupVersionResource) informerfactory.StartableInformer {
	switch opts.InformerType {
	case ktypes.DynamicInformer:
		return getInformerFilteredDynamic(c, opts, g)
	case ktypes.MetadataInformer:
		return getInformerFilteredMetadata(c, opts, g)
	default:
		return getInformerFiltered(c, opts, g)
	}
}

func getInformerFilteredDynamic(c ClientGetter, opts ktypes.InformerOptions, g schema.GroupVersionResource) informerfactory.StartableInformer {
	return c.Informers().InformerFor(g, opts, func() cache.SharedIndexInformer {
		inf := cache.NewSharedIndexInformerWithOptions(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					options.FieldSelector = opts.FieldSelector
					options.LabelSelector = opts.LabelSelector
					return c.Dynamic().Resource(g).Namespace(opts.Namespace).List(context.Background(), options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					options.FieldSelector = opts.FieldSelector
					options.LabelSelector = opts.LabelSelector
					return c.Dynamic().Resource(g).Namespace(opts.Namespace).Watch(context.Background(), options)
				},
			},
			&unstructured.Unstructured{},
			cache.SharedIndexInformerOptions{
				ResyncPeriod:      0,
				Indexers:          cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				ObjectDescription: g.String(),
			},
		)
		setupInformer(opts, inf)
		return inf
	})
}

func getInformerFilteredMetadata(c ClientGetter, opts ktypes.InformerOptions, g schema.GroupVersionResource) informerfactory.StartableInformer {
	return c.Informers().InformerFor(g, opts, func() cache.SharedIndexInformer {
		inf := cache.NewSharedIndexInformerWithOptions(
			&cache.ListWatch{
				ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
					options.FieldSelector = opts.FieldSelector
					options.LabelSelector = opts.LabelSelector
					return c.Metadata().Resource(g).Namespace(opts.Namespace).List(context.Background(), options)
				},
				WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
					options.FieldSelector = opts.FieldSelector
					options.LabelSelector = opts.LabelSelector
					return c.Metadata().Resource(g).Namespace(opts.Namespace).Watch(context.Background(), options)
				},
			},
			&metav1.PartialObjectMetadata{},
			cache.SharedIndexInformerOptions{
				ResyncPeriod:      0,
				Indexers:          cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
				ObjectDescription: g.String(),
			},
		)
		setupInformer(opts, inf)
		return inf
	})
}

func setupInformer(opts ktypes.InformerOptions, inf cache.SharedIndexInformer) {
	// It is important to set this in the newFunc rather than after InformerFor to avoid
	// https://github.com/kubernetes/kubernetes/issues/117869
	if opts.ObjectTransform != nil {
		_ = inf.SetTransform(opts.ObjectTransform)
	} else {
		_ = inf.SetTransform(stripUnusedFields)
	}
	if err := inf.SetWatchErrorHandler(informermetric.ErrorHandlerForCluster(opts.Cluster)); err != nil {
		log.Debugf("failed to set watch handler, informer may already be started: %v", err)
	}
}

// stripUnusedFields is the transform function for shared informers,
// it removes unused fields from objects before they are stored in the cache to save memory.
func stripUnusedFields(obj any) (any, error) {
	t, ok := obj.(metav1.ObjectMetaAccessor)
	if !ok {
		// shouldn't happen
		return obj, nil
	}
	// ManagedFields is large and we never use it
	t.GetObjectMeta().SetManagedFields(nil)
	return obj, nil
}

var registerType []any = make([]any, 0)

// Register provides the TypeRegistration to the underlying
// store to enable dynamic object translation
func Register[T runtime.Object](reg TypeRegistration[T]) {
	kubetypes.Register[T](reg)
	registerType = append(registerType, reg)
}

// TypeRegistration represents the necessary methods
// to provide a custom type to the kubeclient informer mechanism
type TypeRegistration[T runtime.Object] interface {
	kubetypes.RegisterType[T]

	// ListWatchFunc provides the necessary methods for list and
	// watch for the informer
	ListWatch(c ClientGetter, opts ktypes.InformerOptions) cache.ListerWatcher

	// Object provides the runtime.Object for this TypeRegistration
	Object() T
}

type gvrMatch interface {
	GetGVR() schema.GroupVersionResource
}

func NewTypeRegistration[T runtime.Object](gvr schema.GroupVersionResource, gvk config.GroupVersionKind, obj T, lw func(c ClientGetter, o ktypes.InformerOptions) cache.ListerWatcher) TypeRegistration[T] {
	return &internalTypeReg[T]{
		gvr: gvr,
		gvk: gvk,
		obj: obj,
		lw:  lw,
	}
}

type internalTypeReg[T runtime.Object] struct {
	lw  func(c ClientGetter, o ktypes.InformerOptions) cache.ListerWatcher
	gvr schema.GroupVersionResource
	gvk config.GroupVersionKind
	obj T
}

func (t *internalTypeReg[T]) GetGVK() config.GroupVersionKind {
	return t.gvk
}

func (t *internalTypeReg[T]) GetGVR() schema.GroupVersionResource {
	return t.gvr
}

func (t *internalTypeReg[T]) ListWatch(c ClientGetter, o ktypes.InformerOptions) cache.ListerWatcher {
	return t.lw(c, o)
}

func (t *internalTypeReg[T]) Object() T {
	return t.obj
}
