// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schema"
)

type IstioConfigStore struct {
	ConfigDescriptorStub        func() schema.Set
	configDescriptorMutex       sync.RWMutex
	configDescriptorArgsForCall []struct{}
	configDescriptorReturns     struct {
		result1 schema.Set
	}
	configDescriptorReturnsOnCall map[int]struct {
		result1 schema.Set
	}
	GetStub        func(typ, name, namespace string) *model.Config
	getMutex       sync.RWMutex
	getArgsForCall []struct {
		typ       string
		name      string
		namespace string
	}
	getReturns struct {
		result1 *model.Config
	}
	getReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	ListStub        func(typ, namespace string) ([]model.Config, error)
	listMutex       sync.RWMutex
	listArgsForCall []struct {
		typ       string
		namespace string
	}
	listReturns struct {
		result1 []model.Config
		result2 error
	}
	listReturnsOnCall map[int]struct {
		result1 []model.Config
		result2 error
	}
	CreateStub        func(config model.Config) (revision string, err error)
	createMutex       sync.RWMutex
	createArgsForCall []struct {
		config model.Config
	}
	createReturns struct {
		result1 string
		result2 error
	}
	createReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	UpdateStub        func(config model.Config) (newRevision string, err error)
	updateMutex       sync.RWMutex
	updateArgsForCall []struct {
		config model.Config
	}
	updateReturns struct {
		result1 string
		result2 error
	}
	updateReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	DeleteStub        func(typ, name, namespace string) error
	deleteMutex       sync.RWMutex
	deleteArgsForCall []struct {
		typ       string
		name      string
		namespace string
	}
	deleteReturns struct {
		result1 error
	}
	deleteReturnsOnCall map[int]struct {
		result1 error
	}
	ServiceEntriesStub        func() []model.Config
	serviceEntriesMutex       sync.RWMutex
	serviceEntriesArgsForCall []struct{}
	serviceEntriesReturns     struct {
		result1 []model.Config
	}
	serviceEntriesReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	GatewaysStub        func(workloadLabels labels.Collection) []model.Config
	gatewaysMutex       sync.RWMutex
	gatewaysArgsForCall []struct {
		workloadLabels labels.Collection
	}
	gatewaysReturns struct {
		result1 []model.Config
	}
	gatewaysReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	EnvoyFilterStub        func(workloadLabels labels.Collection) *model.Config
	envoyFilterMutex       sync.RWMutex
	envoyFilterArgsForCall []struct {
		workloadLabels labels.Collection
	}
	envoyFilterReturns struct {
		result1 *model.Config
	}
	envoyFilterReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	HTTPAPISpecByDestinationStub        func(instance *model.ServiceInstance) []model.Config
	hTTPAPISpecByDestinationMutex       sync.RWMutex
	hTTPAPISpecByDestinationArgsForCall []struct {
		instance *model.ServiceInstance
	}
	hTTPAPISpecByDestinationReturns struct {
		result1 []model.Config
	}
	hTTPAPISpecByDestinationReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	QuotaSpecByDestinationStub        func(instance *model.ServiceInstance) []model.Config
	quotaSpecByDestinationMutex       sync.RWMutex
	quotaSpecByDestinationArgsForCall []struct {
		instance *model.ServiceInstance
	}
	quotaSpecByDestinationReturns struct {
		result1 []model.Config
	}
	quotaSpecByDestinationReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	AuthenticationPolicyForWorkloadStub        func(service *model.Service, labels labels.Instance, port *model.Port) *model.Config
	authenticationPolicyForWorkloadMutex       sync.RWMutex
	authenticationPolicyForWorkloadArgsForCall []struct {
		service *model.Service
		labels  labels.Instance
		port    *model.Port
	}
	authenticationPolicyForWorkloadReturns struct {
		result1 *model.Config
	}
	authenticationPolicyForWorkloadReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	ServiceRolesStub        func(namespace string) []model.Config
	serviceRolesMutex       sync.RWMutex
	serviceRolesArgsForCall []struct {
		namespace string
	}
	serviceRolesReturns struct {
		result1 []model.Config
	}
	serviceRolesReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	ServiceRoleBindingsStub        func(namespace string) []model.Config
	serviceRoleBindingsMutex       sync.RWMutex
	serviceRoleBindingsArgsForCall []struct {
		namespace string
	}
	serviceRoleBindingsReturns struct {
		result1 []model.Config
	}
	serviceRoleBindingsReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	RbacConfigStub        func() *model.Config
	rbacConfigMutex       sync.RWMutex
	rbacConfigArgsForCall []struct{}
	rbacConfigReturns     struct {
		result1 *model.Config
	}
	rbacConfigReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	ClusterRbacConfigStub        func() *model.Config
	clusterRbacConfigMutex       sync.RWMutex
	clusterRbacConfigArgsForCall []struct{}
	clusterRbacConfigReturns     struct {
		result1 *model.Config
	}
	clusterRbacConfigReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *IstioConfigStore) ConfigDescriptor() schema.Set {
	fake.configDescriptorMutex.Lock()
	ret, specificReturn := fake.configDescriptorReturnsOnCall[len(fake.configDescriptorArgsForCall)]
	fake.configDescriptorArgsForCall = append(fake.configDescriptorArgsForCall, struct{}{})
	fake.recordInvocation("ConfigDescriptor", []interface{}{})
	fake.configDescriptorMutex.Unlock()
	if fake.ConfigDescriptorStub != nil {
		return fake.ConfigDescriptorStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.configDescriptorReturns.result1
}

func (fake *IstioConfigStore) ConfigDescriptorCallCount() int {
	fake.configDescriptorMutex.RLock()
	defer fake.configDescriptorMutex.RUnlock()
	return len(fake.configDescriptorArgsForCall)
}

func (fake *IstioConfigStore) ConfigDescriptorReturns(result1 schema.Set) {
	fake.ConfigDescriptorStub = nil
	fake.configDescriptorReturns = struct {
		result1 schema.Set
	}{result1}
}

func (fake *IstioConfigStore) ConfigDescriptorReturnsOnCall(i int, result1 schema.Set) {
	fake.ConfigDescriptorStub = nil
	if fake.configDescriptorReturnsOnCall == nil {
		fake.configDescriptorReturnsOnCall = make(map[int]struct {
			result1 schema.Set
		})
	}
	fake.configDescriptorReturnsOnCall[i] = struct {
		result1 schema.Set
	}{result1}
}

func (fake *IstioConfigStore) Get(typ string, name string, namespace string) *model.Config {
	fake.getMutex.Lock()
	ret, specificReturn := fake.getReturnsOnCall[len(fake.getArgsForCall)]
	fake.getArgsForCall = append(fake.getArgsForCall, struct {
		typ       string
		name      string
		namespace string
	}{typ, name, namespace})
	fake.recordInvocation("Get", []interface{}{typ, name, namespace})
	fake.getMutex.Unlock()
	if fake.GetStub != nil {
		return fake.GetStub(typ, name, namespace)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.getReturns.result1
}

func (fake *IstioConfigStore) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *IstioConfigStore) GetArgsForCall(i int) (string, string, string) {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return fake.getArgsForCall[i].typ, fake.getArgsForCall[i].name, fake.getArgsForCall[i].namespace
}

func (fake *IstioConfigStore) GetReturns(result1 *model.Config) {
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) GetReturnsOnCall(i int, result1 *model.Config) {
	fake.GetStub = nil
	if fake.getReturnsOnCall == nil {
		fake.getReturnsOnCall = make(map[int]struct {
			result1 *model.Config
		})
	}
	fake.getReturnsOnCall[i] = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) List(typ string, namespace string) ([]model.Config, error) {
	fake.listMutex.Lock()
	ret, specificReturn := fake.listReturnsOnCall[len(fake.listArgsForCall)]
	fake.listArgsForCall = append(fake.listArgsForCall, struct {
		typ       string
		namespace string
	}{typ, namespace})
	fake.recordInvocation("List", []interface{}{typ, namespace})
	fake.listMutex.Unlock()
	if fake.ListStub != nil {
		return fake.ListStub(typ, namespace)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.listReturns.result1, fake.listReturns.result2
}

func (fake *IstioConfigStore) ListCallCount() int {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return len(fake.listArgsForCall)
}

func (fake *IstioConfigStore) ListArgsForCall(i int) (string, string) {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return fake.listArgsForCall[i].typ, fake.listArgsForCall[i].namespace
}

func (fake *IstioConfigStore) ListReturns(result1 []model.Config, result2 error) {
	fake.ListStub = nil
	fake.listReturns = struct {
		result1 []model.Config
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) ListReturnsOnCall(i int, result1 []model.Config, result2 error) {
	fake.ListStub = nil
	if fake.listReturnsOnCall == nil {
		fake.listReturnsOnCall = make(map[int]struct {
			result1 []model.Config
			result2 error
		})
	}
	fake.listReturnsOnCall[i] = struct {
		result1 []model.Config
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) Create(config model.Config) (revision string, err error) {
	fake.createMutex.Lock()
	ret, specificReturn := fake.createReturnsOnCall[len(fake.createArgsForCall)]
	fake.createArgsForCall = append(fake.createArgsForCall, struct {
		config model.Config
	}{config})
	fake.recordInvocation("Create", []interface{}{config})
	fake.createMutex.Unlock()
	if fake.CreateStub != nil {
		return fake.CreateStub(config)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.createReturns.result1, fake.createReturns.result2
}

func (fake *IstioConfigStore) CreateCallCount() int {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return len(fake.createArgsForCall)
}

func (fake *IstioConfigStore) CreateArgsForCall(i int) model.Config {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return fake.createArgsForCall[i].config
}

func (fake *IstioConfigStore) CreateReturns(result1 string, result2 error) {
	fake.CreateStub = nil
	fake.createReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) CreateReturnsOnCall(i int, result1 string, result2 error) {
	fake.CreateStub = nil
	if fake.createReturnsOnCall == nil {
		fake.createReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.createReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) Update(config model.Config) (newRevision string, err error) {
	fake.updateMutex.Lock()
	ret, specificReturn := fake.updateReturnsOnCall[len(fake.updateArgsForCall)]
	fake.updateArgsForCall = append(fake.updateArgsForCall, struct {
		config model.Config
	}{config})
	fake.recordInvocation("Update", []interface{}{config})
	fake.updateMutex.Unlock()
	if fake.UpdateStub != nil {
		return fake.UpdateStub(config)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.updateReturns.result1, fake.updateReturns.result2
}

func (fake *IstioConfigStore) UpdateCallCount() int {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	return len(fake.updateArgsForCall)
}

func (fake *IstioConfigStore) UpdateArgsForCall(i int) model.Config {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	return fake.updateArgsForCall[i].config
}

func (fake *IstioConfigStore) UpdateReturns(result1 string, result2 error) {
	fake.UpdateStub = nil
	fake.updateReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) UpdateReturnsOnCall(i int, result1 string, result2 error) {
	fake.UpdateStub = nil
	if fake.updateReturnsOnCall == nil {
		fake.updateReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.updateReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) Delete(typ string, name string, namespace string) error {
	fake.deleteMutex.Lock()
	ret, specificReturn := fake.deleteReturnsOnCall[len(fake.deleteArgsForCall)]
	fake.deleteArgsForCall = append(fake.deleteArgsForCall, struct {
		typ       string
		name      string
		namespace string
	}{typ, name, namespace})
	fake.recordInvocation("Delete", []interface{}{typ, name, namespace})
	fake.deleteMutex.Unlock()
	if fake.DeleteStub != nil {
		return fake.DeleteStub(typ, name, namespace)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.deleteReturns.result1
}

func (fake *IstioConfigStore) DeleteCallCount() int {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return len(fake.deleteArgsForCall)
}

func (fake *IstioConfigStore) DeleteArgsForCall(i int) (string, string, string) {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return fake.deleteArgsForCall[i].typ, fake.deleteArgsForCall[i].name, fake.deleteArgsForCall[i].namespace
}

func (fake *IstioConfigStore) DeleteReturns(result1 error) {
	fake.DeleteStub = nil
	fake.deleteReturns = struct {
		result1 error
	}{result1}
}

func (fake *IstioConfigStore) DeleteReturnsOnCall(i int, result1 error) {
	fake.DeleteStub = nil
	if fake.deleteReturnsOnCall == nil {
		fake.deleteReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.deleteReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *IstioConfigStore) ServiceEntries() []model.Config {
	fake.serviceEntriesMutex.Lock()
	ret, specificReturn := fake.serviceEntriesReturnsOnCall[len(fake.serviceEntriesArgsForCall)]
	fake.serviceEntriesArgsForCall = append(fake.serviceEntriesArgsForCall, struct{}{})
	fake.recordInvocation("ServiceEntries", []interface{}{})
	fake.serviceEntriesMutex.Unlock()
	if fake.ServiceEntriesStub != nil {
		return fake.ServiceEntriesStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.serviceEntriesReturns.result1
}

func (fake *IstioConfigStore) ServiceEntriesCallCount() int {
	fake.serviceEntriesMutex.RLock()
	defer fake.serviceEntriesMutex.RUnlock()
	return len(fake.serviceEntriesArgsForCall)
}

func (fake *IstioConfigStore) ServiceEntriesReturns(result1 []model.Config) {
	fake.ServiceEntriesStub = nil
	fake.serviceEntriesReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceEntriesReturnsOnCall(i int, result1 []model.Config) {
	fake.ServiceEntriesStub = nil
	if fake.serviceEntriesReturnsOnCall == nil {
		fake.serviceEntriesReturnsOnCall = make(map[int]struct {
			result1 []model.Config
		})
	}
	fake.serviceEntriesReturnsOnCall[i] = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) Gateways(workloadLabels labels.Collection) []model.Config {
	fake.gatewaysMutex.Lock()
	ret, specificReturn := fake.gatewaysReturnsOnCall[len(fake.gatewaysArgsForCall)]
	fake.gatewaysArgsForCall = append(fake.gatewaysArgsForCall, struct {
		workloadLabels labels.Collection
	}{workloadLabels})
	fake.recordInvocation("Gateways", []interface{}{workloadLabels})
	fake.gatewaysMutex.Unlock()
	if fake.GatewaysStub != nil {
		return fake.GatewaysStub(workloadLabels)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.gatewaysReturns.result1
}

func (fake *IstioConfigStore) GatewaysCallCount() int {
	fake.gatewaysMutex.RLock()
	defer fake.gatewaysMutex.RUnlock()
	return len(fake.gatewaysArgsForCall)
}

func (fake *IstioConfigStore) GatewaysArgsForCall(i int) labels.Collection {
	fake.gatewaysMutex.RLock()
	defer fake.gatewaysMutex.RUnlock()
	return fake.gatewaysArgsForCall[i].workloadLabels
}

func (fake *IstioConfigStore) GatewaysReturns(result1 []model.Config) {
	fake.GatewaysStub = nil
	fake.gatewaysReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) GatewaysReturnsOnCall(i int, result1 []model.Config) {
	fake.GatewaysStub = nil
	if fake.gatewaysReturnsOnCall == nil {
		fake.gatewaysReturnsOnCall = make(map[int]struct {
			result1 []model.Config
		})
	}
	fake.gatewaysReturnsOnCall[i] = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) EnvoyFilter(workloadLabels labels.Collection) *model.Config {
	fake.envoyFilterMutex.Lock()
	ret, specificReturn := fake.envoyFilterReturnsOnCall[len(fake.envoyFilterArgsForCall)]
	fake.envoyFilterArgsForCall = append(fake.envoyFilterArgsForCall, struct {
		workloadLabels labels.Collection
	}{workloadLabels})
	fake.recordInvocation("EnvoyFilter", []interface{}{workloadLabels})
	fake.envoyFilterMutex.Unlock()
	if fake.EnvoyFilterStub != nil {
		return fake.EnvoyFilterStub(workloadLabels)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.envoyFilterReturns.result1
}

func (fake *IstioConfigStore) EnvoyFilterCallCount() int {
	fake.envoyFilterMutex.RLock()
	defer fake.envoyFilterMutex.RUnlock()
	return len(fake.envoyFilterArgsForCall)
}

func (fake *IstioConfigStore) EnvoyFilterArgsForCall(i int) labels.Collection {
	fake.envoyFilterMutex.RLock()
	defer fake.envoyFilterMutex.RUnlock()
	return fake.envoyFilterArgsForCall[i].workloadLabels
}

func (fake *IstioConfigStore) EnvoyFilterReturns(result1 *model.Config) {
	fake.EnvoyFilterStub = nil
	fake.envoyFilterReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) EnvoyFilterReturnsOnCall(i int, result1 *model.Config) {
	fake.EnvoyFilterStub = nil
	if fake.envoyFilterReturnsOnCall == nil {
		fake.envoyFilterReturnsOnCall = make(map[int]struct {
			result1 *model.Config
		})
	}
	fake.envoyFilterReturnsOnCall[i] = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) HTTPAPISpecByDestination(instance *model.ServiceInstance) []model.Config {
	fake.hTTPAPISpecByDestinationMutex.Lock()
	ret, specificReturn := fake.hTTPAPISpecByDestinationReturnsOnCall[len(fake.hTTPAPISpecByDestinationArgsForCall)]
	fake.hTTPAPISpecByDestinationArgsForCall = append(fake.hTTPAPISpecByDestinationArgsForCall, struct {
		instance *model.ServiceInstance
	}{instance})
	fake.recordInvocation("HTTPAPISpecByDestination", []interface{}{instance})
	fake.hTTPAPISpecByDestinationMutex.Unlock()
	if fake.HTTPAPISpecByDestinationStub != nil {
		return fake.HTTPAPISpecByDestinationStub(instance)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.hTTPAPISpecByDestinationReturns.result1
}

func (fake *IstioConfigStore) HTTPAPISpecByDestinationCallCount() int {
	fake.hTTPAPISpecByDestinationMutex.RLock()
	defer fake.hTTPAPISpecByDestinationMutex.RUnlock()
	return len(fake.hTTPAPISpecByDestinationArgsForCall)
}

func (fake *IstioConfigStore) HTTPAPISpecByDestinationArgsForCall(i int) *model.ServiceInstance {
	fake.hTTPAPISpecByDestinationMutex.RLock()
	defer fake.hTTPAPISpecByDestinationMutex.RUnlock()
	return fake.hTTPAPISpecByDestinationArgsForCall[i].instance
}

func (fake *IstioConfigStore) HTTPAPISpecByDestinationReturns(result1 []model.Config) {
	fake.HTTPAPISpecByDestinationStub = nil
	fake.hTTPAPISpecByDestinationReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) HTTPAPISpecByDestinationReturnsOnCall(i int, result1 []model.Config) {
	fake.HTTPAPISpecByDestinationStub = nil
	if fake.hTTPAPISpecByDestinationReturnsOnCall == nil {
		fake.hTTPAPISpecByDestinationReturnsOnCall = make(map[int]struct {
			result1 []model.Config
		})
	}
	fake.hTTPAPISpecByDestinationReturnsOnCall[i] = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) QuotaSpecByDestination(instance *model.ServiceInstance) []model.Config {
	fake.quotaSpecByDestinationMutex.Lock()
	ret, specificReturn := fake.quotaSpecByDestinationReturnsOnCall[len(fake.quotaSpecByDestinationArgsForCall)]
	fake.quotaSpecByDestinationArgsForCall = append(fake.quotaSpecByDestinationArgsForCall, struct {
		instance *model.ServiceInstance
	}{instance})
	fake.recordInvocation("QuotaSpecByDestination", []interface{}{instance})
	fake.quotaSpecByDestinationMutex.Unlock()
	if fake.QuotaSpecByDestinationStub != nil {
		return fake.QuotaSpecByDestinationStub(instance)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.quotaSpecByDestinationReturns.result1
}

func (fake *IstioConfigStore) QuotaSpecByDestinationCallCount() int {
	fake.quotaSpecByDestinationMutex.RLock()
	defer fake.quotaSpecByDestinationMutex.RUnlock()
	return len(fake.quotaSpecByDestinationArgsForCall)
}

func (fake *IstioConfigStore) QuotaSpecByDestinationArgsForCall(i int) *model.ServiceInstance {
	fake.quotaSpecByDestinationMutex.RLock()
	defer fake.quotaSpecByDestinationMutex.RUnlock()
	return fake.quotaSpecByDestinationArgsForCall[i].instance
}

func (fake *IstioConfigStore) QuotaSpecByDestinationReturns(result1 []model.Config) {
	fake.QuotaSpecByDestinationStub = nil
	fake.quotaSpecByDestinationReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) QuotaSpecByDestinationReturnsOnCall(i int, result1 []model.Config) {
	fake.QuotaSpecByDestinationStub = nil
	if fake.quotaSpecByDestinationReturnsOnCall == nil {
		fake.quotaSpecByDestinationReturnsOnCall = make(map[int]struct {
			result1 []model.Config
		})
	}
	fake.quotaSpecByDestinationReturnsOnCall[i] = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) AuthenticationPolicyForWorkload(service *model.Service, l labels.Instance, port *model.Port) *model.Config {
	fake.authenticationPolicyForWorkloadMutex.Lock()
	ret, specificReturn := fake.authenticationPolicyForWorkloadReturnsOnCall[len(fake.authenticationPolicyForWorkloadArgsForCall)]
	fake.authenticationPolicyForWorkloadArgsForCall = append(fake.authenticationPolicyForWorkloadArgsForCall, struct {
		service *model.Service
		labels  labels.Instance
		port    *model.Port
	}{service, l, port})
	fake.recordInvocation("AuthenticationPolicyForWorkload", []interface{}{service, l, port})
	fake.authenticationPolicyForWorkloadMutex.Unlock()
	if fake.AuthenticationPolicyForWorkloadStub != nil {
		return fake.AuthenticationPolicyForWorkloadStub(service, l, port)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.authenticationPolicyForWorkloadReturns.result1
}

func (fake *IstioConfigStore) AuthenticationPolicyForWorkloadCallCount() int {
	fake.authenticationPolicyForWorkloadMutex.RLock()
	defer fake.authenticationPolicyForWorkloadMutex.RUnlock()
	return len(fake.authenticationPolicyForWorkloadArgsForCall)
}

func (fake *IstioConfigStore) AuthenticationPolicyForWorkloadArgsForCall(i int) (*model.Service, labels.Instance, *model.Port) {
	fake.authenticationPolicyForWorkloadMutex.RLock()
	defer fake.authenticationPolicyForWorkloadMutex.RUnlock()
	return fake.authenticationPolicyForWorkloadArgsForCall[i].service, fake.authenticationPolicyForWorkloadArgsForCall[i].labels, fake.authenticationPolicyForWorkloadArgsForCall[i].port
}

func (fake *IstioConfigStore) AuthenticationPolicyForWorkloadReturns(result1 *model.Config) {
	fake.AuthenticationPolicyForWorkloadStub = nil
	fake.authenticationPolicyForWorkloadReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) AuthenticationPolicyForWorkloadReturnsOnCall(i int, result1 *model.Config) {
	fake.AuthenticationPolicyForWorkloadStub = nil
	if fake.authenticationPolicyForWorkloadReturnsOnCall == nil {
		fake.authenticationPolicyForWorkloadReturnsOnCall = make(map[int]struct {
			result1 *model.Config
		})
	}
	fake.authenticationPolicyForWorkloadReturnsOnCall[i] = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceRoles(namespace string) []model.Config {
	fake.serviceRolesMutex.Lock()
	ret, specificReturn := fake.serviceRolesReturnsOnCall[len(fake.serviceRolesArgsForCall)]
	fake.serviceRolesArgsForCall = append(fake.serviceRolesArgsForCall, struct {
		namespace string
	}{namespace})
	fake.recordInvocation("ServiceRoles", []interface{}{namespace})
	fake.serviceRolesMutex.Unlock()
	if fake.ServiceRolesStub != nil {
		return fake.ServiceRolesStub(namespace)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.serviceRolesReturns.result1
}

func (fake *IstioConfigStore) ServiceRolesCallCount() int {
	fake.serviceRolesMutex.RLock()
	defer fake.serviceRolesMutex.RUnlock()
	return len(fake.serviceRolesArgsForCall)
}

func (fake *IstioConfigStore) ServiceRolesArgsForCall(i int) string {
	fake.serviceRolesMutex.RLock()
	defer fake.serviceRolesMutex.RUnlock()
	return fake.serviceRolesArgsForCall[i].namespace
}

func (fake *IstioConfigStore) ServiceRolesReturns(result1 []model.Config) {
	fake.ServiceRolesStub = nil
	fake.serviceRolesReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceRolesReturnsOnCall(i int, result1 []model.Config) {
	fake.ServiceRolesStub = nil
	if fake.serviceRolesReturnsOnCall == nil {
		fake.serviceRolesReturnsOnCall = make(map[int]struct {
			result1 []model.Config
		})
	}
	fake.serviceRolesReturnsOnCall[i] = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceRoleBindings(namespace string) []model.Config {
	fake.serviceRoleBindingsMutex.Lock()
	ret, specificReturn := fake.serviceRoleBindingsReturnsOnCall[len(fake.serviceRoleBindingsArgsForCall)]
	fake.serviceRoleBindingsArgsForCall = append(fake.serviceRoleBindingsArgsForCall, struct {
		namespace string
	}{namespace})
	fake.recordInvocation("ServiceRoleBindings", []interface{}{namespace})
	fake.serviceRoleBindingsMutex.Unlock()
	if fake.ServiceRoleBindingsStub != nil {
		return fake.ServiceRoleBindingsStub(namespace)
	}
	if specificReturn {
		return ret.result1
	}
	return fake.serviceRoleBindingsReturns.result1
}

func (fake *IstioConfigStore) ServiceRoleBindingsCallCount() int {
	fake.serviceRoleBindingsMutex.RLock()
	defer fake.serviceRoleBindingsMutex.RUnlock()
	return len(fake.serviceRoleBindingsArgsForCall)
}

func (fake *IstioConfigStore) ServiceRoleBindingsArgsForCall(i int) string {
	fake.serviceRoleBindingsMutex.RLock()
	defer fake.serviceRoleBindingsMutex.RUnlock()
	return fake.serviceRoleBindingsArgsForCall[i].namespace
}

func (fake *IstioConfigStore) ServiceRoleBindingsReturns(result1 []model.Config) {
	fake.ServiceRoleBindingsStub = nil
	fake.serviceRoleBindingsReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceRoleBindingsReturnsOnCall(i int, result1 []model.Config) {
	fake.ServiceRoleBindingsStub = nil
	if fake.serviceRoleBindingsReturnsOnCall == nil {
		fake.serviceRoleBindingsReturnsOnCall = make(map[int]struct {
			result1 []model.Config
		})
	}
	fake.serviceRoleBindingsReturnsOnCall[i] = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) RbacConfig() *model.Config {
	fake.rbacConfigMutex.Lock()
	ret, specificReturn := fake.rbacConfigReturnsOnCall[len(fake.rbacConfigArgsForCall)]
	fake.rbacConfigArgsForCall = append(fake.rbacConfigArgsForCall, struct{}{})
	fake.recordInvocation("RbacConfig", []interface{}{})
	fake.rbacConfigMutex.Unlock()
	if fake.RbacConfigStub != nil {
		return fake.RbacConfigStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.rbacConfigReturns.result1
}

func (fake *IstioConfigStore) RbacConfigCallCount() int {
	fake.rbacConfigMutex.RLock()
	defer fake.rbacConfigMutex.RUnlock()
	return len(fake.rbacConfigArgsForCall)
}

func (fake *IstioConfigStore) RbacConfigReturns(result1 *model.Config) {
	fake.RbacConfigStub = nil
	fake.rbacConfigReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) RbacConfigReturnsOnCall(i int, result1 *model.Config) {
	fake.RbacConfigStub = nil
	if fake.rbacConfigReturnsOnCall == nil {
		fake.rbacConfigReturnsOnCall = make(map[int]struct {
			result1 *model.Config
		})
	}
	fake.rbacConfigReturnsOnCall[i] = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) ClusterRbacConfig() *model.Config {
	fake.clusterRbacConfigMutex.Lock()
	ret, specificReturn := fake.clusterRbacConfigReturnsOnCall[len(fake.clusterRbacConfigArgsForCall)]
	fake.clusterRbacConfigArgsForCall = append(fake.clusterRbacConfigArgsForCall, struct{}{})
	fake.recordInvocation("ClusterRbacConfig", []interface{}{})
	fake.clusterRbacConfigMutex.Unlock()
	if fake.ClusterRbacConfigStub != nil {
		return fake.ClusterRbacConfigStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.clusterRbacConfigReturns.result1
}

func (fake *IstioConfigStore) ClusterRbacConfigCallCount() int {
	fake.clusterRbacConfigMutex.RLock()
	defer fake.clusterRbacConfigMutex.RUnlock()
	return len(fake.clusterRbacConfigArgsForCall)
}

func (fake *IstioConfigStore) ClusterRbacConfigReturns(result1 *model.Config) {
	fake.ClusterRbacConfigStub = nil
	fake.clusterRbacConfigReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) ClusterRbacConfigReturnsOnCall(i int, result1 *model.Config) {
	fake.ClusterRbacConfigStub = nil
	if fake.clusterRbacConfigReturnsOnCall == nil {
		fake.clusterRbacConfigReturnsOnCall = make(map[int]struct {
			result1 *model.Config
		})
	}
	fake.clusterRbacConfigReturnsOnCall[i] = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.configDescriptorMutex.RLock()
	defer fake.configDescriptorMutex.RUnlock()
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	fake.serviceEntriesMutex.RLock()
	defer fake.serviceEntriesMutex.RUnlock()
	fake.gatewaysMutex.RLock()
	defer fake.gatewaysMutex.RUnlock()
	fake.envoyFilterMutex.RLock()
	defer fake.envoyFilterMutex.RUnlock()
	fake.hTTPAPISpecByDestinationMutex.RLock()
	defer fake.hTTPAPISpecByDestinationMutex.RUnlock()
	fake.quotaSpecByDestinationMutex.RLock()
	defer fake.quotaSpecByDestinationMutex.RUnlock()
	fake.authenticationPolicyForWorkloadMutex.RLock()
	defer fake.authenticationPolicyForWorkloadMutex.RUnlock()
	fake.serviceRolesMutex.RLock()
	defer fake.serviceRolesMutex.RUnlock()
	fake.serviceRoleBindingsMutex.RLock()
	defer fake.serviceRoleBindingsMutex.RUnlock()
	fake.rbacConfigMutex.RLock()
	defer fake.rbacConfigMutex.RUnlock()
	fake.clusterRbacConfigMutex.RLock()
	defer fake.clusterRbacConfigMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *IstioConfigStore) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ model.IstioConfigStore = new(IstioConfigStore)
