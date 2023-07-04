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

package controller

import (
	"net/netip"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	v1 "k8s.io/api/core/v1"
	klabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"

	"istio.io/api/networking/v1alpha3"
	apiv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/serviceregistry/kube"
	"istio.io/istio/pilot/pkg/serviceregistry/serviceentry"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/config/schema/kind"
	kubeutil "istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	kubelabels "istio.io/istio/pkg/kube/labels"
	"istio.io/istio/pkg/maps"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/pkg/workloadapi"
)

type AmbientIndex interface {
	Lookup(key string) []*model.AddressInfo
	All() []*model.AddressInfo
	WorkloadsForWaypoint(scope model.WaypointScope) []*model.WorkloadInfo
	Waypoint(scope model.WaypointScope) []netip.Addr
	CalculateUpdatedWorkloads(pods map[string]*v1.Pod, workloadEntries map[networkAddress]*apiv1alpha3.WorkloadEntry, c *Controller) map[model.ConfigKey]struct{}
	HandleSelectedNamespace(ns string, pods []*v1.Pod, c *Controller)
}

// AmbientIndexImpl maintains an index of ambient WorkloadInfo objects by various keys.
// These are intentionally pre-computed based on events such that lookups are efficient.
type AmbientIndexImpl struct {
	mu sync.RWMutex
	// byService indexes by Service namespaced hostname. A given Service can map to
	// many workloads associated, indexed by workload uid.
	byService map[string]map[string]*model.WorkloadInfo
	// byHostname indexes workloads by their pod hostname. Pod hostnames, unlike
	// services are globally unique.
	byHostname map[string]*model.WorkloadInfo
	// byPod indexes by network/podIP address.
	byPod map[networkAddress]*model.WorkloadInfo
	// byWorkloadEntry indexes by WorkloadEntry IP address.
	byWorkloadEntry map[networkAddress]*model.WorkloadInfo
	// byUID indexes by workloads by their uid
	byUID map[string]*model.WorkloadInfo
	// serviceByAddr are indexed by the network/clusterIP
	serviceByAddr map[networkAddress]*model.ServiceInfo
	// serviceByHostname indexes services by just their hostname. Service hostnames
	// are only guaranteed to be unique within a namespace, so it is possible to
	// have multiple services with the same hostname.
	serviceByHostname map[string][]*model.ServiceInfo

	// Map of Scope -> address
	waypoints map[model.WaypointScope]*workloadapi.GatewayAddress
}

func workloadToAddressInfo(w *workloadapi.Workload) *model.AddressInfo {
	return &model.AddressInfo{
		Address: &workloadapi.Address{
			Type: &workloadapi.Address_Workload{
				Workload: w,
			},
		},
	}
}

func serviceToAddressInfo(s *workloadapi.Service) *model.AddressInfo {
	return &model.AddressInfo{
		Address: &workloadapi.Address{
			Type: &workloadapi.Address_Service{
				Service: s,
			},
		},
	}
}

// name format: <cluster>/<group>/<kind>/<namespace>/<name></section-name>
func (c *Controller) generatePodUID(p *v1.Pod) string {
	return c.clusterID.String() + "//" + "Pod/" + p.Namespace + "/" + p.Name
}

// servicesByNamespacedHostname returns the service with the given namespace and hostname. If
// the provided namespace is a wildcard ("*"), all services with the hostname are returned.
func (a *AmbientIndexImpl) servicesByNamespacedHostname(namespace, hostname string) []*model.ServiceInfo {
	out := make([]*model.ServiceInfo, 0)
	if services := a.serviceByHostname[hostname]; services != nil {
		if namespace == "*" {
			// The query was for all namespaces. Return all services with the hostname.
			out = append(out, services...)
		} else {
			// Return only the service with the matching hostname.
			for _, svc := range services {
				if svc.Namespace == namespace {
					out = append(out, svc)
					break
				}
			}
		}
	}
	return out
}

// Lookup finds the list of AddressInfos for a given key.
// network/IP -> return associated pod Workload or the Service and its corresponding Workloads
// namespace/hostname -> return the Service and its corresponding Workloads
//
// NOTE: As an interface method of AmbientIndex, this locks the index.
func (a *AmbientIndexImpl) Lookup(key string) []*model.AddressInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// uid is primary key, attempt lookup first
	if wl, f := a.byUID[key]; f {
		return []*model.AddressInfo{workloadToAddressInfo(wl.Workload)}
	}

	part1, part2, found := strings.Cut(key, "/")
	if !found {
		log.Warnf(`key (%v) did not contain the expected "/" character`, key)
		return nil
	}

	// First check to see if it's a network address for a workload or service.
	res := make([]*model.AddressInfo, 0)
	if _, err := netip.ParseAddr(part2); err == nil {
		networkAddr := networkAddress{network: part1, ip: part2}
		// First look at pod...
		if p, f := a.byPod[networkAddr]; f {
			return []*model.AddressInfo{workloadToAddressInfo(p.Workload)}
		}
		// Next, look at WorkloadEntries
		if w, f := a.byWorkloadEntry[networkAddr]; f {
			return []*model.AddressInfo{workloadToAddressInfo(w.Workload)}
		}

		// Fallback to service VIP. Note: these IP ranges should be non-overlapping.
		// When a Service lookup is performed, the service and its workloads are returned
		if s, exists := a.serviceByAddr[networkAddr]; exists {
			res = append(res, serviceToAddressInfo(s.Service))
			for _, wl := range a.byService[s.ResourceName()] {
				res = append(res, workloadToAddressInfo(wl.Workload))
			}
		}

		return res
	}

	// The query must be in the namespace/hostname format.
	namespace := part1
	hostname := part2

	// Lookup service(s) first, then workloads.
	if services := a.servicesByNamespacedHostname(namespace, hostname); len(services) > 0 {
		for _, svc := range services {
			res = append(res, serviceToAddressInfo(svc.Service))

			// When adding a service, add all of its workloads as well.
			for _, wl := range a.byService[key] {
				res = append(res, workloadToAddressInfo(wl.Workload))
			}
		}
	} else if wl, f := a.byHostname[hostname]; f {
		res = append(res, workloadToAddressInfo(wl.Workload))
	}
	return res
}

func (a *AmbientIndexImpl) dropWorkloadFromService(namespacedHostname string, workloadUID string) {
	wls := a.byService[namespacedHostname]
	delete(wls, workloadUID)
}

func (a *AmbientIndexImpl) insertWorkloadToService(namespacedHostname string, workload *model.WorkloadInfo) {
	if _, ok := a.byService[namespacedHostname]; !ok {
		a.byService[namespacedHostname] = map[string]*model.WorkloadInfo{}
	}
	a.byService[namespacedHostname][workload.Uid] = workload
}

func (a *AmbientIndexImpl) updateWaypoint(sa model.WaypointScope, addr *workloadapi.GatewayAddress, isDelete bool) map[model.ConfigKey]struct{} {
	updates := sets.New[model.ConfigKey]()
	// Update Waypoints for Pods
	a.updateWaypointForWorkload(a.byPod, sa, addr, isDelete, updates)
	// Update Waypoints for WorkloadEntries
	a.updateWaypointForWorkload(a.byWorkloadEntry, sa, addr, isDelete, updates)
	return updates
}

// All return all known workloads and services. Result is un-ordered
//
// NOTE: As an interface method of AmbientIndex, this locks the index.
func (a *AmbientIndexImpl) All() []*model.AddressInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	res := make([]*model.AddressInfo, 0, len(a.byPod)+len(a.serviceByAddr)+len(a.byWorkloadEntry))
	for _, services := range a.serviceByHostname {
		for _, svc := range services {
			res = append(res, serviceToAddressInfo(svc.Service))
		}
	}
	// byPod and byWorkloadEntry will not have any duplicates, so we can just iterate over that.
	for _, wl := range a.byPod {
		res = append(res, workloadToAddressInfo(wl.Workload))
	}
	for _, wl := range a.byWorkloadEntry {
		res = append(res, workloadToAddressInfo(wl.Workload))
	}
	return res
}

// WorkloadsForWaypoint returns all workload information matching the scope.
//
// NOTE: As an interface method of AmbientIndex, this locks the index.
func (a *AmbientIndexImpl) WorkloadsForWaypoint(scope model.WaypointScope) []*model.WorkloadInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var res []*model.WorkloadInfo
	// TODO: try to precompute
	for _, w := range a.byPod {
		if a.matchesScope(scope, w) {
			res = append(res, w)
		}
	}
	for _, w := range a.byWorkloadEntry {
		if a.matchesScope(scope, w) {
			res = append(res, w)
		}
	}
	return res
}

func (c *Controller) WorkloadsForWaypoint(scope model.WaypointScope) []*model.WorkloadInfo {
	return c.ambientIndex.WorkloadsForWaypoint(scope)
}

// Waypoint returns the addresses of the waypoints matching the scope.
//
// NOTE: As an interface method of AmbientIndex, this locks the index.
func (a *AmbientIndexImpl) Waypoint(scope model.WaypointScope) []netip.Addr {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// TODO need to handle case where waypoints are dualstack/have multiple addresses
	if addr, f := a.waypoints[scope]; f {
		switch address := addr.Destination.(type) {
		case *workloadapi.GatewayAddress_Address:
			if ip, ok := netip.AddrFromSlice(address.Address.GetAddress()); ok {
				return []netip.Addr{ip}
			}
		case *workloadapi.GatewayAddress_Hostname:
			// TODO
		}
	}

	// Now look for namespace-wide
	scope.ServiceAccount = ""
	if addr, f := a.waypoints[scope]; f {
		switch address := addr.Destination.(type) {
		case *workloadapi.GatewayAddress_Address:
			if ip, ok := netip.AddrFromSlice(address.Address.GetAddress()); ok {
				return []netip.Addr{ip}
			}
		case *workloadapi.GatewayAddress_Hostname:
			// TODO
		}
	}

	return nil
}

// Waypoint finds all waypoint IP addresses for a given scope.  Performs first a Namespace+ServiceAccount
// then falls back to any Namespace wide waypoints
func (c *Controller) Waypoint(scope model.WaypointScope) []netip.Addr {
	return c.ambientIndex.Waypoint(scope)
}

func (a *AmbientIndexImpl) matchesScope(scope model.WaypointScope, w *model.WorkloadInfo) bool {
	if w.Namespace != scope.Namespace {
		return false
	}
	// Filter out waypoints.
	if w.Labels[constants.ManagedGatewayLabel] == constants.ManagedGatewayMeshControllerLabel {
		return false
	}
	if len(scope.ServiceAccount) == 0 {
		// We are a namespace wide waypoint. SA scope take precedence.
		// Check if there is one for this workloads service account
		if _, f := a.waypoints[model.WaypointScope{Namespace: scope.Namespace, ServiceAccount: w.ServiceAccount}]; f {
			return false
		}
		return true
	}
	return w.ServiceAccount == scope.ServiceAccount
}

func (c *Controller) constructService(svc *v1.Service) *model.ServiceInfo {
	ports := make([]*workloadapi.Port, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		ports = append(ports, &workloadapi.Port{
			ServicePort: uint32(p.Port),
			TargetPort:  uint32(p.TargetPort.IntVal),
		})
	}

	// TODO this is only checking one controller - we may be missing service vips for instances in another cluster
	vips := getVIPs(svc)
	addrs := make([]*workloadapi.NetworkAddress, 0, len(vips))
	for _, vip := range vips {
		addrs = append(addrs, &workloadapi.NetworkAddress{
			Network: c.Network(vip, make(labels.Instance, 0)).String(),
			Address: netip.MustParseAddr(vip).AsSlice(),
		})
	}

	return &model.ServiceInfo{
		Service: &workloadapi.Service{
			Name:      svc.Name,
			Namespace: svc.Namespace,
			Hostname:  c.hostname(svc),
			Addresses: addrs,
			Ports:     ports,
		},
	}
}

func (c *Controller) hostname(svc *v1.Service) string {
	return string(kube.ServiceHostname(svc.Name, svc.Namespace, c.opts.DomainSuffix))
}

func (c *Controller) namespacedHostname(svc *v1.Service) string {
	return namespacedHostname(svc.Namespace, c.hostname(svc))
}

func namespacedHostname(namespace, hostname string) string {
	return namespace + "/" + hostname
}

// NOTE: Mutex is locked prior to being called.
func (a *AmbientIndexImpl) extractWorkload(p *v1.Pod, c *Controller) *model.WorkloadInfo {
	if p == nil || !IsPodRunning(p) || p.Spec.HostNetwork {
		return nil
	}
	var waypoint *workloadapi.GatewayAddress
	if p.Labels[constants.ManagedGatewayLabel] == constants.ManagedGatewayMeshControllerLabel {
		// Waypoints do not have waypoints
	} else {
		// First check for a waypoint for our SA explicit
		found := false
		if waypoint, found = a.waypoints[model.WaypointScope{Namespace: p.Namespace, ServiceAccount: p.Spec.ServiceAccountName}]; !found {
			// if there are none, check namespace wide waypoints
			waypoint = a.waypoints[model.WaypointScope{Namespace: p.Namespace}]
		}
	}

	policies := c.selectorAuthorizationPolicies(p.Namespace, p.Labels)
	policies = append(policies, c.convertedSelectorPeerAuthentications(p.Namespace, p.Labels)...)
	wl := c.constructWorkload(p, waypoint, policies)
	if wl == nil {
		return nil
	}
	return &model.WorkloadInfo{
		Workload: wl,
		Labels:   p.Labels,
	}
}

func (c *Controller) setupIndex() AmbientIndex {
	idx := AmbientIndexImpl{
		byService:         map[string]map[string]*model.WorkloadInfo{},
		byHostname:        map[string]*model.WorkloadInfo{},
		byPod:             map[networkAddress]*model.WorkloadInfo{},
		byWorkloadEntry:   map[networkAddress]*model.WorkloadInfo{},
		byUID:             map[string]*model.WorkloadInfo{},
		waypoints:         map[model.WaypointScope]*workloadapi.GatewayAddress{},
		serviceByAddr:     map[networkAddress]*model.ServiceInfo{},
		serviceByHostname: map[string][]*model.ServiceInfo{},
	}

	podHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			idx.mu.Lock()
			defer idx.mu.Unlock()
			updates := idx.handlePod(nil, obj, false, c)
			if len(updates) > 0 {
				c.opts.XDSUpdater.ConfigUpdate(&model.PushRequest{
					ConfigsUpdated: updates,
					Reason:         []model.TriggerReason{model.AmbientUpdate},
				})
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			idx.mu.Lock()
			defer idx.mu.Unlock()
			updates := idx.handlePod(oldObj, newObj, false, c)
			if len(updates) > 0 {
				c.opts.XDSUpdater.ConfigUpdate(&model.PushRequest{
					ConfigsUpdated: updates,
					Reason:         []model.TriggerReason{model.AmbientUpdate},
				})
			}
		},
		DeleteFunc: func(obj any) {
			idx.mu.Lock()
			defer idx.mu.Unlock()
			updates := idx.handlePod(nil, obj, true, c)
			if len(updates) > 0 {
				c.opts.XDSUpdater.ConfigUpdate(&model.PushRequest{
					ConfigsUpdated: updates,
					Reason:         []model.TriggerReason{model.AmbientUpdate},
				})
			}
		},
	}

	c.podsClient.AddEventHandler(podHandler)

	// Handle WorkloadEntries.
	c.configController.RegisterEventHandler(gvk.WorkloadEntry, func(oldCfg config.Config, newCfg config.Config, ev model.Event) {
		var oldWkEntrySpec *v1alpha3.WorkloadEntry
		if ev == model.EventUpdate {
			oldWkEntrySpec = serviceentry.ConvertWorkloadEntry(oldCfg)
		}
		var oldWkEntry *apiv1alpha3.WorkloadEntry
		if oldWkEntrySpec != nil {
			oldWkEntry = &apiv1alpha3.WorkloadEntry{
				ObjectMeta: oldCfg.ToObjectMeta(),
				Spec:       *oldWkEntrySpec.DeepCopy(),
			}
		}
		newWkEntrySpec := serviceentry.ConvertWorkloadEntry(newCfg)
		var newWkEntry *apiv1alpha3.WorkloadEntry
		if newWkEntrySpec != nil {
			newWkEntry = &apiv1alpha3.WorkloadEntry{
				ObjectMeta: newCfg.ToObjectMeta(),
				Spec:       *newWkEntrySpec.DeepCopy(),
			}
		}

		idx.mu.Lock()
		defer idx.mu.Unlock()
		updates := idx.handleWorkloadEntry(oldWkEntry, newWkEntry, ev == model.EventDelete, c)
		if len(updates) > 0 {
			c.opts.XDSUpdater.ConfigUpdate(&model.PushRequest{
				Full:           false,
				ConfigsUpdated: updates,
				Reason:         []model.TriggerReason{model.AmbientUpdate},
			})
		}
	})

	serviceHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			idx.mu.Lock()
			defer idx.mu.Unlock()
			updates := idx.handleService(obj, false, c)
			if len(updates) > 0 {
				c.opts.XDSUpdater.ConfigUpdate(&model.PushRequest{
					ConfigsUpdated: updates,
					Reason:         []model.TriggerReason{model.AmbientUpdate},
				})
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			idx.mu.Lock()
			defer idx.mu.Unlock()
			updates := idx.handleService(oldObj, true, c)
			updates2 := idx.handleService(newObj, false, c)
			if updates == nil {
				updates = updates2
			} else {
				for k, v := range updates2 {
					updates[k] = v
				}
			}

			if len(updates) > 0 {
				c.opts.XDSUpdater.ConfigUpdate(&model.PushRequest{
					ConfigsUpdated: updates,
					Reason:         []model.TriggerReason{model.AmbientUpdate},
				})
			}
		},
		DeleteFunc: func(obj any) {
			idx.mu.Lock()
			defer idx.mu.Unlock()
			updates := idx.handleService(obj, true, c)
			if len(updates) > 0 {
				c.opts.XDSUpdater.ConfigUpdate(&model.PushRequest{
					ConfigsUpdated: updates,
					Reason:         []model.TriggerReason{model.AmbientUpdate},
				})
			}
		},
	}
	c.services.AddEventHandler(serviceHandler)
	return &idx
}

// NOTE: Mutex is locked prior to being called.
func (a *AmbientIndexImpl) handlePod(oldObj, newObj any, isDelete bool, c *Controller) sets.Set[model.ConfigKey] {
	p := controllers.Extract[*v1.Pod](newObj)
	old := controllers.Extract[*v1.Pod](oldObj)
	if old != nil {
		// compare only labels and pod phase, which are what we care about
		if maps.Equal(old.Labels, p.Labels) &&
			maps.Equal(old.Annotations, p.Annotations) &&
			old.Status.Phase == p.Status.Phase &&
			IsPodReady(old) == IsPodReady(p) {
			return nil
		}
	}

	updates := sets.New[model.ConfigKey]()

	var wl *model.WorkloadInfo
	if !isDelete {
		wl = a.extractWorkload(p, c)
	}
	wlNetwork := c.Network(p.Status.PodIP, p.Labels).String()
	networkAddr := networkAddress{network: wlNetwork, ip: p.Status.PodIP}
	uid := c.generatePodUID(p)
	oldWl := a.byUID[uid]
	if wl == nil {
		// This is an explicit delete event, or there is no longer a Workload to create (pod NotReady, etc)
		delete(a.byPod, networkAddr)
		delete(a.byUID, uid)
		if oldWl != nil {
			// If we already knew about this workload, we need to make sure we drop all service references as well
			for namespacedHostname := range oldWl.Services {
				a.dropWorkloadFromService(namespacedHostname, oldWl.ResourceName())
			}
			// Delete the index by hostname.
			delete(a.byHostname, oldWl.Hostname)
			log.Debugf("%v: workload removed, pushing", p.Status.PodIP)
			// TODO: namespace for network?
			updates.Insert(model.ConfigKey{Kind: kind.Address, Name: oldWl.ResourceName()})
			return updates
		}
		// It was a 'delete' for a resource we didn't know yet, no need to send an event

		return updates
	}
	if oldWl != nil && proto.Equal(wl.Workload, oldWl.Workload) {
		log.Debugf("%v: no change, skipping", wl.ResourceName())

		return updates
	}
	for _, networkAddr := range networkAddressFromWorkload(wl) {
		a.byPod[networkAddr] = wl
	}

	// Update the index by hostname.
	a.byHostname[wl.Hostname] = wl

	a.byUID[wl.Uid] = wl
	if oldWl != nil {
		// For updates, we will drop the service and then add the new ones back. This could be optimized
		for namespacedHostname := range oldWl.Services {
			a.dropWorkloadFromService(namespacedHostname, oldWl.ResourceName())
		}
	}
	// Update the service indexes as well, as needed
	for namespacedHostname := range wl.Services {
		a.insertWorkloadToService(namespacedHostname, wl)
	}

	log.Debugf("%v: workload updated, pushing", wl.ResourceName())
	updates.Insert(model.ConfigKey{Kind: kind.Address, Name: wl.ResourceName()})

	return updates
}

func networkAddressFromWorkload(wl *model.WorkloadInfo) []networkAddress {
	networkAddrs := make([]networkAddress, 0, len(wl.Addresses))
	for _, addr := range wl.Addresses {
		ip, _ := netip.AddrFromSlice(addr)
		networkAddrs = append(networkAddrs, networkAddress{network: wl.Network, ip: ip.String()})
	}
	return networkAddrs
}

// NOTE: Mutex is locked prior to being called.
func (a *AmbientIndexImpl) handleService(obj any, isDelete bool, c *Controller) sets.Set[model.ConfigKey] {
	svc := controllers.Extract[*v1.Service](obj)
	updates := sets.New[model.ConfigKey]()

	if svc.Labels[constants.ManagedGatewayLabel] == constants.ManagedGatewayMeshControllerLabel {
		scope := model.WaypointScope{Namespace: svc.Namespace, ServiceAccount: svc.Annotations[constants.WaypointServiceAccount]}

		// TODO get IP+Port from the Gateway CRD
		// https://github.com/istio/istio/issues/44230
		if svc.Spec.ClusterIP == v1.ClusterIPNone {
			// TODO handle headless Service
			log.Warn("headless service currently not supported as a waypoint")
			return updates
		}
		waypointPort := uint32(15008)
		for _, p := range svc.Spec.Ports {
			if strings.Contains(p.Name, "hbone") {
				waypointPort = uint32(p.Port)
			}
		}
		svcIP := netip.MustParseAddr(svc.Spec.ClusterIP)
		addr := &workloadapi.GatewayAddress{
			Destination: &workloadapi.GatewayAddress_Address{
				Address: &workloadapi.NetworkAddress{
					Network: c.Network(svcIP.String(), make(labels.Instance, 0)).String(),
					Address: svcIP.AsSlice(),
				},
			},
			Port: waypointPort,
		}

		if isDelete {
			if proto.Equal(a.waypoints[scope], addr) {
				delete(a.waypoints, scope)
				updates.Merge(a.updateWaypoint(scope, addr, true))
			}
		} else {
			if !proto.Equal(a.waypoints[scope], addr) {
				a.waypoints[scope] = addr
				updates.Merge(a.updateWaypoint(scope, addr, false))
			}
		}
	}

	si := c.constructService(svc)
	networkAddrs := make([]networkAddress, 0, len(si.Addresses))
	for _, addr := range si.Addresses {
		if vip, ok := netip.AddrFromSlice(addr.Address); ok {
			networkAddrs = append(networkAddrs, networkAddress{
				ip:      vip.String(),
				network: addr.Network,
			})
		}
	}
	pods := c.getPodsInService(svc)
	wls := make(map[string]*model.WorkloadInfo, len(pods))
	for _, p := range pods {
		// Can be nil if it's not ready, hostNetwork, etc
		wl := a.extractWorkload(p, c)
		if wl != nil {
			// Update the pod, since it now has new VIP info
			for _, networkAddr := range networkAddressFromWorkload(wl) {
				a.byPod[networkAddr] = wl
			}
			a.byUID[wl.Uid] = wl
			wls[wl.Uid] = wl
		}
	}

	workloadEntries := c.getWorkloadEntriesInService(svc)
	for _, w := range workloadEntries {
		wl := a.extractWorkloadEntry(w, c)
		// Can be nil if the WorkloadEntry IP has not been mapped yet
		//
		// Note: this is a defensive check that mimics the logic for
		// pods above. WorkloadEntries are mapped by their IP address
		// in the following cases:
		// 1. WorkloadEntry add/update
		// 2. AuthorizationPolicy add/update
		// 3. Namespace Ambient label add/update
		if wl != nil {
			// Update the WorkloadEntry, since it now has new VIP info
			for _, networkAddr := range networkAddressFromWorkload(wl) {
				a.byWorkloadEntry[networkAddr] = wl
			}
			a.byUID[wl.Uid] = wl
			wls[wl.Uid] = wl
		}
	}

	// We send an update for each *workload* IP address previously in the service; they may have changed
	namespacedName := si.ResourceName()
	for _, wl := range a.byService[namespacedName] {
		updates.Insert(model.ConfigKey{Kind: kind.Address, Name: wl.ResourceName()})
	}
	// Update indexes
	if isDelete {
		for _, networkAddr := range networkAddrs {
			delete(a.serviceByAddr, networkAddr)
		}
		// Delete the mapping to workload.
		delete(a.byService, namespacedName)

		// Delete the index by hostname.
		services := a.serviceByHostname[si.Hostname]
		for index, svc := range services {
			if svc.Namespace == si.Namespace {
				services = append(services[:index], services[index+1:]...)
				a.serviceByHostname[si.Hostname] = services
				break
			}
		}

		updates.Insert(model.ConfigKey{Kind: kind.Address, Name: namespacedName})
	} else {
		for _, networkAddr := range networkAddrs {
			a.serviceByAddr[networkAddr] = si
		}
		a.byService[namespacedName] = wls

		// Update the index by hostname.
		services := a.serviceByHostname[si.Hostname]
		found := false
		for index, svc := range services {
			if svc.Namespace == si.Namespace {
				found = true
				services[index] = si
				a.serviceByHostname[si.Hostname] = services
				break
			}
		}
		if !found {
			a.serviceByHostname[si.Hostname] = append(services, si)
		}

		updates.Insert(model.ConfigKey{Kind: kind.Address, Name: namespacedName})
	}
	// Fetch updates again, in case it changed from adding new workloads
	for _, wl := range a.byService[namespacedName] {
		updates.Insert(model.ConfigKey{Kind: kind.Address, Name: wl.ResourceName()})
	}

	return updates
}

func (c *Controller) getPodsInService(svc *v1.Service) []*v1.Pod {
	if svc.Spec.Selector == nil {
		// services with nil selectors match nothing, not everything.
		return nil
	}
	return c.podsClient.List(svc.Namespace, klabels.ValidatedSetSelector(svc.Spec.Selector))
}

// AddressInformation returns all AddressInfo's in the cluster.
// This may be scoped to specific subsets by specifying a non-empty addresses field
func (c *Controller) AddressInformation(addresses sets.String) ([]*model.AddressInfo, []string) {
	if len(addresses) == 0 {
		// Full update
		return c.ambientIndex.All(), nil
	}
	var wls []*model.AddressInfo
	var removed []string
	for addr := range addresses {
		wl := c.ambientIndex.Lookup(addr)
		if len(wl) == 0 {
			removed = append(removed, addr)
		} else {
			wls = append(wls, wl...)
		}
	}
	return wls, removed
}

func (c *Controller) constructWorkload(pod *v1.Pod, waypoint *workloadapi.GatewayAddress, policies []string) *workloadapi.Workload {
	workloadServices := map[string]*workloadapi.PortList{}
	allServices := c.services.List(pod.Namespace, klabels.Everything())
	if services := getPodServices(allServices, pod); len(services) > 0 {
		for _, svc := range services {
			// Build the ports for the service.
			ports := &workloadapi.PortList{}
			for _, port := range svc.Spec.Ports {
				if port.Protocol != v1.ProtocolTCP {
					continue
				}
				targetPort, err := FindPort(pod, &port)
				if err != nil {
					log.Debug(err)
					continue
				}
				ports.Ports = append(ports.Ports, &workloadapi.Port{
					ServicePort: uint32(port.Port),
					TargetPort:  uint32(targetPort),
				})
			}

			workloadServices[c.namespacedHostname(svc)] = ports
		}
	}

	addresses := make([][]byte, 0, len(pod.Status.PodIPs))
	for _, podIP := range pod.Status.PodIPs {
		addresses = append(addresses, parseIP(podIP.IP))
	}

	wl := &workloadapi.Workload{
		Uid:                   c.generatePodUID(pod),
		Name:                  pod.Name,
		Addresses:             addresses,
		Hostname:              pod.Spec.Hostname,
		Network:               c.Network(pod.Status.PodIP, pod.Labels).String(),
		Namespace:             pod.Namespace,
		ServiceAccount:        pod.Spec.ServiceAccountName,
		Node:                  pod.Spec.NodeName,
		Services:              workloadServices,
		AuthorizationPolicies: policies,
		Status:                workloadapi.WorkloadStatus_HEALTHY,
		ClusterId:             c.Cluster().String(),
		Waypoint:              waypoint,
	}
	if !IsPodReady(pod) {
		wl.Status = workloadapi.WorkloadStatus_UNHEALTHY
	}
	if td := spiffe.GetTrustDomain(); td != "cluster.local" {
		wl.TrustDomain = td
	}

	wl.WorkloadName, wl.WorkloadType = workloadNameAndType(pod)
	wl.CanonicalName, wl.CanonicalRevision = kubelabels.CanonicalService(pod.Labels, wl.WorkloadName)

	if pod.Annotations[constants.AmbientRedirection] == constants.AmbientRedirectionEnabled {
		// Configured for override
		wl.TunnelProtocol = workloadapi.TunnelProtocol_HBONE
	}
	// Otherwise supports tunnel directly
	if model.SupportsTunnel(pod.Labels, model.TunnelHTTP) {
		wl.TunnelProtocol = workloadapi.TunnelProtocol_HBONE
		wl.NativeTunnel = true
	}
	return wl
}

func parseIP(ip string) []byte {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	return addr.AsSlice()
}

// internal object used for indexing in ambientindex maps
type networkAddress struct {
	network string
	ip      string
}

func (n *networkAddress) String() string {
	return n.network + "/" + n.ip
}

func getVIPs(svc *v1.Service) []string {
	res := make([]string, 0)
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != v1.ClusterIPNone {
		res = append(res, svc.Spec.ClusterIP)
	}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		res = append(res, ing.IP)
	}
	return res
}

func (c *Controller) AdditionalPodSubscriptions(
	proxy *model.Proxy,
	allAddresses sets.String,
	currentSubs sets.String,
) sets.String {
	shouldSubscribe := sets.New[string]()

	// First, we want to handle VIP subscriptions. Example:
	// Client subscribes to VIP1. Pod1, part of VIP1, is sent.
	// The client wouldn't be explicitly subscribed to Pod1, so it would normally ignore it.
	// Since it is a part of VIP1 which we are subscribe to, add it to the subscriptions
	for addr := range allAddresses {
		for _, wl := range model.ExtractWorkloadsFromAddresses(c.ambientIndex.Lookup(addr)) {
			// We may have gotten an update for Pod, but are subscribed to a Service.
			// We need to force a subscription on the Pod as well
			for namespacedHostname := range wl.Services {
				if currentSubs.Contains(namespacedHostname) {
					shouldSubscribe.Insert(wl.ResourceName())
					break
				}
			}
		}
	}

	// Next, as an optimization, we will send all node-local endpoints
	if nodeName := proxy.Metadata.NodeName; nodeName != "" {
		for _, wl := range model.ExtractWorkloadsFromAddresses(c.ambientIndex.All()) {
			if wl.Node == nodeName {
				n := wl.ResourceName()
				if currentSubs.Contains(n) {
					continue
				}
				shouldSubscribe.Insert(n)
			}
		}
	}

	return shouldSubscribe
}

func workloadNameAndType(pod *v1.Pod) (string, workloadapi.WorkloadType) {
	objMeta, typeMeta := kubeutil.GetDeployMetaFromPod(pod)
	switch typeMeta.Kind {
	case "Deployment":
		return objMeta.Name, workloadapi.WorkloadType_DEPLOYMENT
	case "Job":
		return objMeta.Name, workloadapi.WorkloadType_JOB
	case "CronJob":
		return objMeta.Name, workloadapi.WorkloadType_CRONJOB
	default:
		return pod.Name, workloadapi.WorkloadType_POD
	}
}
