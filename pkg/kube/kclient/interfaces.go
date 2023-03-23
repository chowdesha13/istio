package kclient

import (
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	"istio.io/istio/pkg/kube/controllers"
)

type Untyped = Informer[controllers.Object]

// Reader wraps a Kubernetes client providing cached read access.
// This is based on informers, so most of the same caveats to informers apply here.
type Reader[T controllers.Object] interface {
	// Get looks up an object by name and namespace. If it does not exist, nil is returned
	Get(name, namespace string) T
	// List looks up an object by namespace and labels.
	// Use metav1.NamespaceAll and klabels.Everything() to select everything.
	List(namespace string, selector klabels.Selector) []T
}

type Informer[T controllers.Object] interface {
	Reader[T]
	// ListUnfiltered is like List but ignores any *client side* filters previously configured.
	ListUnfiltered(namespace string, selector klabels.Selector) []T
	// AddEventHandler inserts a handler. The handler will be called for all Create/Update/Removals.
	// When ShutdownHandlers is called, the handler is removed.
	AddEventHandler(h cache.ResourceEventHandler)
	// HasSynced returns true when the informer is initially populated and that all handlers added
	// via AddEventHandler have been called with the initial state.
	// note: this differs from a standard informer HasSynced, which does not check handlers have been called.
	HasSynced() bool
	// ShutdownHandlers terminates all handlers added by AddEventHandler.
	// Warning: this only applies to handlers called via AddEventHandler; any handlers directly added
	// to the underlying informer are not touched
	ShutdownHandlers()
}

type Writer[T controllers.Object] interface {
	// Create creates a resource, returning the newly applied resource.
	Create(object T) (T, error)
	// Update updates a resource, returning the newly applied resource.
	Update(object T) (T, error)
	// UpdateStatus updates a resource's status, returning the newly applied resource.
	UpdateStatus(object T) (T, error)
	// Delete removes a resource.
	Delete(name, namespace string) error
}

type ReadWriter[T controllers.Object] interface {
	Reader[T]
	Writer[T]
}

// Client wraps a Kubernetes client providing cached read access and direct write access.
type Client[T controllers.Object] interface {
	Reader[T]
	Writer[T]
	Informer[T]
}
