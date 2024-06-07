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

package nodeagent

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	klabels "k8s.io/apimachinery/pkg/labels"

	"istio.io/istio/cni/pkg/util"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/monitoring"
)

var (
	eventTypeTag = monitoring.CreateLabel("type")
	EventTotals  = monitoring.NewSum(
		"nodeagent_reconcile_events_total",
		"The total number of node agent reconcile events.",
	)
)

type K8sHandlers interface {
	GetPodIfAmbient(podName, podNamespace string) (*corev1.Pod, error)
	GetActiveAmbientPodSnapshot() []*corev1.Pod
	Start()
}

type InformerHandlers struct {
	ctx             context.Context
	dataplane       MeshDataplane
	systemNamespace string

	queue      controllers.Queue
	pods       kclient.Client[*corev1.Pod]
	namespaces kclient.Client[*corev1.Namespace]
}

func setupHandlers(ctx context.Context, kubeClient kube.Client, dataplane MeshDataplane, systemNamespace string) *InformerHandlers {
	s := &InformerHandlers{ctx: ctx, dataplane: dataplane, systemNamespace: systemNamespace}
	s.queue = controllers.NewQueue("ambient",
		controllers.WithGenericReconciler(s.reconcile),
		controllers.WithMaxAttempts(5),
	)
	// We only need to handle pods on our node
	s.pods = kclient.NewFiltered[*corev1.Pod](kubeClient, kclient.Filter{FieldSelector: "spec.nodeName=" + NodeName})
	s.pods.AddEventHandler(controllers.FromEventHandler(func(o controllers.Event) {
		s.queue.Add(o)
	}))

	// Namespaces could be anything though, so we watch all of those
	//
	// NOTE that we are requeueing namespaces here explicitly to work around
	// test flakes with the fake kube client in `pkg/kube/client.go` -
	// because we are using `List()` in the handler, without this requeue,
	// the fake client will sometimes drop pod events leading to test flakes.
	//
	// WaitForCacheSync *helps*, but does not entirely fix this problem
	s.namespaces = kclient.New[*corev1.Namespace](kubeClient)
	s.namespaces.AddEventHandler(controllers.FromEventHandler(func(o controllers.Event) {
		s.queue.Add(o)
	}))

	return s
}

// GetPodIfAmbient looks up a pod. It returns:
// * An error if the pod cannot be found
// * nil if the pod is found, but does not have ambient enabled
// * the pod, if it is found and ambient is enabled
func (s *InformerHandlers) GetPodIfAmbient(podName, podNamespace string) (*corev1.Pod, error) {
	ns := s.namespaces.Get(podNamespace, "")
	if ns == nil {
		return nil, fmt.Errorf("failed to find namespace %v", ns)
	}
	pod := s.pods.Get(podName, podNamespace)
	if pod == nil {
		return nil, fmt.Errorf("failed to find pod %v", ns)
	}
	if util.PodRedirectionEnabled(ns, pod) {
		return pod, nil
	}
	return nil, nil
}

func (s *InformerHandlers) Start() {
	kube.WaitForCacheSync("informer", s.ctx.Done(), s.pods.HasSynced, s.namespaces.HasSynced)
	go s.queue.Run(s.ctx.Done())
}

// Gets a point-in-time snapshot of all pods that are CURRENTLY ambient enabled
// (as per control plane annotation)
// Note that this is not the same thing as SHOULD be enabled or WILL be enabled.
// This is only used for building the initial snapshot ATM.
func (s *InformerHandlers) GetActiveAmbientPodSnapshot() []*corev1.Pod {
	var pods []*corev1.Pod
	for _, pod := range s.pods.List(metav1.NamespaceAll, klabels.Everything()) {
		ns := s.namespaces.Get(pod.Namespace, "")
		if ns == nil {
			log.Warnf("failed to find namespace %s for pod %s", pod.Namespace, pod.Name)
		}

		// Exclude ztunnels, and terminated daemonset pods
		// from the snapshot.
		if !util.IsZtunnelPod(s.systemNamespace, pod) &&
			!kube.CheckPodTerminal(pod) &&
			util.PodRedirectionActive(pod) {
			pods = append(pods, pod)
		}
	}
	return pods
}

// EnqueueNamespace takes a Namespace and enqueues all Pod objects that make need an update
// TODO it is sort of pointless/confusing/implicit to populate Old and New with the same reference here
func (s *InformerHandlers) enqueueNamespace(o controllers.Object) {
	namespace := o.GetName()
	labels := o.GetLabels()
	matchAmbient := labels[constants.DataplaneModeLabel] == constants.DataplaneModeAmbient
	if matchAmbient {
		log.Infof("Namespace %s is enabled in ambient mesh", namespace)
	} else {
		log.Infof("Namespace %s is disabled from ambient mesh", namespace)
	}
	for _, pod := range s.pods.List(namespace, klabels.Everything()) {
		// ztunnel pods are never "added to/removed from the mesh", so do not fire
		// spurious events for them to avoid triggering extra
		// ztunnel node reconciliation checks.
		if !util.IsZtunnelPod(s.systemNamespace, pod) {
			log.Debugf("Enqueuing pod %s/%s", pod.Namespace, pod.Name)
			s.queue.Add(controllers.Event{
				New:   pod,
				Old:   pod,
				Event: controllers.EventUpdate,
			})
		}
	}
}

func (s *InformerHandlers) reconcile(input any) error {
	event := input.(controllers.Event)
	switch event.Latest().(type) {
	case *corev1.Namespace:
		return s.reconcileNamespace(input)
	case *corev1.Pod:
		return s.reconcilePod(input)
	default:
		return fmt.Errorf("unexpected event type: %+v", input)
	}
}

func (s *InformerHandlers) reconcileNamespace(input any) error {
	event := input.(controllers.Event)
	ns := event.Latest().(*corev1.Namespace)

	switch event.Event {
	case controllers.EventAdd:
		log.Debugf("Namespace %s added", ns.Name)
		s.enqueueNamespace(ns)

	case controllers.EventUpdate:
		newNs := event.New.(*corev1.Namespace)
		oldNs := event.Old.(*corev1.Namespace)

		if getModeLabel(oldNs.Labels) != getModeLabel(newNs.Labels) {
			log.Debugf("Namespace %s updated", newNs.Name)
			s.enqueueNamespace(newNs)
		}
	}
	return nil
}

func getModeLabel(m map[string]string) string {
	if m == nil {
		return ""
	}
	return m[constants.DataplaneModeLabel]
}

func (s *InformerHandlers) reconcilePod(input any) error {
	event := input.(controllers.Event)
	pod := event.Latest().(*corev1.Pod)

	defer EventTotals.With(eventTypeTag.Value(event.Event.String())).Increment()

	switch event.Event {
	case controllers.EventAdd:
		// pod was added to our cache
		// we get here in 2 cases:
		// 1. new pod was created on our node
		// 2. we were restarted and current existing pods are added to our cache

		// We have no good way to distinguish between these two cases from here. But we don't need to!
		// Existing pods will be handled by the dataplane using `GetAmbientPods`,
		// and the initial enqueueNamespace, and new pods will be handled by the CNI.

	case controllers.EventUpdate:
		// For update, we just need to handle opt outs
		newPod := event.New.(*corev1.Pod)
		oldPod := event.Old.(*corev1.Pod)
		ns := s.namespaces.Get(newPod.Namespace, "")
		if ns == nil {
			return fmt.Errorf("failed to find namespace %v", ns)
		}
		wasAnnotated := oldPod.Annotations != nil && oldPod.Annotations[constants.AmbientRedirection] == constants.AmbientRedirectionEnabled
		isAnnotated := newPod.Annotations != nil && newPod.Annotations[constants.AmbientRedirection] == constants.AmbientRedirectionEnabled
		shouldBeEnabled := util.PodRedirectionEnabled(ns, newPod)
		isTerminated := kube.CheckPodTerminal(newPod)
		// Check intent (labels) versus status (annotation) - is there a delta we need to fix?
		changeNeeded := (isAnnotated != shouldBeEnabled) && !isTerminated

		// nolint: lll
		log.Debugf("pod %s events: wasAnnotated(%v), isAnnotated(%v), shouldBeEnabled(%v), changeNeeded(%v), isTerminated(%v), oldPod(%+v), newPod(%+v)",
			pod.Name, wasAnnotated, isAnnotated, shouldBeEnabled, changeNeeded, isTerminated, oldPod.ObjectMeta, newPod.ObjectMeta)

		// If it was a job pod that (a) we captured and (b) just terminated (successfully or otherwise)
		// remove it (the pod process is gone, but kube will keep the Pods around in
		// a terminated || failed state - we should still do cleanup)
		if isAnnotated && isTerminated {
			log.Debugf("deleting pod %s from mesh, reason: isAnnotated(%v), isTerminated(%v)", newPod.Name, isAnnotated, isTerminated)
			// Unlike the other cases, we actually want to use the "old" event for terminated job pods
			// - kubernetes will (weirdly) issue a new status to the pod with no IP on termination, meaning
			// our check of `pod.status` will fail for (some) termination events.
			//
			// We will get subsequent events that append a new status with the IP put back, but it's simpler
			// and safer to just check the old pod status for the IP.
			err := s.dataplane.RemovePodFromMesh(s.ctx, oldPod)
			log.Debugf("RemovePodFromMesh(%s) returned %v", newPod.Name, err)
			return nil
		}

		if !changeNeeded {
			log.Debugf("pod %s update event skipped, reason: changeNeeded(%v)", pod.Name, changeNeeded)
			return nil
		}

		// Pod is not terminated, and has changed in a way we care about - so reconcile
		if !shouldBeEnabled {
			log.Debugf("removing pod %s from mesh, reason: shouldBeEnabled(%v)", newPod.Name, shouldBeEnabled)
			err := s.dataplane.RemovePodFromMesh(s.ctx, pod)
			log.Debugf("RemovePodFromMesh(%s) returned %v", newPod.Name, err)
			// we ignore errors here as we don't want this event to be retried by the queue.
		} else {
			// If oldpod != ready && newpod != ready, but the ambient annotation was added,
			// then assume this event was generated by the CNI plugin labeling the pod on startup,
			// and skip the event.
			//
			// This isn't perfect (someone could manually annotate an unready pod,
			// then install Istio, then the pod goes ready, and we'd miss capture) - but that
			// seems vanishingly unlikely
			wasReady := kube.CheckPodReadyOrComplete(oldPod)
			isReady := kube.CheckPodReadyOrComplete(newPod)
			if wasReady != nil && isReady != nil && isAnnotated {
				log.Infof("pod %s update event skipped, reason: added/labeled by CNI plugin", pod.Name)
				return nil
			}

			log.Debugf("pod %s now matches, adding to mesh", newPod.Name)
			// netns == ""; at this point netns should have been added via the initial snapshot,
			// or via the cni plugin. If it happens to get here before the cni plugin somehow,
			// then we will just fail to add the pod to the mesh, and it will be retried later when cni plugin adds it.

			// We need a pod IP - if the pod was added via the CNI plugin, that plugin told us the IPs
			// for the pod. If this is a pod added via informer, the pod should have already gone thru
			// the CNI plugin chain, and have a PodIP.
			//
			// If PodIPs exists, it is preferred, otherwise fallback to PodIP.
			//
			// If we get to this point and have a pod that really and truly has no IP in either of those,
			// it's not routable at this point and something is wrong/we should discard this event.
			podIPs := util.GetPodIPsIfPresent(pod)
			if len(podIPs) == 0 {
				log.Warnf("pod %s does not appear to have any assigned IPs, not capturing", pod.Name)
				return nil
			}

			err := s.dataplane.AddPodToMesh(s.ctx, pod, podIPs, "")
			if err != nil {
				log.Warnf("AddPodToMesh(%s) returned %v", newPod.Name, err)
			}
		}
	case controllers.EventDelete:
		// We are the only thing that should be annotating the pods for mesh inclusion.
		// If we did, remove it from ztunnel
		if util.PodRedirectionActive(pod) {
			log.Debugf("pod %s is deleted and was annotated, removing from ztunnel", pod.Name)
			err := s.dataplane.DelPodFromMesh(s.ctx, pod)
			if err != nil {
				log.Warnf("DelPodFromMesh(%s) returned %v", pod.Name, err)
			}
		} else {
			log.Debugf("skipped deleting from mesh for pod (%s), pod not in mesh", pod.Name)
		}
	}
	return nil
}
