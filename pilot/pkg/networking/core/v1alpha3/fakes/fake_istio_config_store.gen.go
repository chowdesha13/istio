// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	sync "sync"

	model "istio.io/istio/pilot/pkg/model"
	labels "istio.io/istio/pkg/config/labels"
	schema "istio.io/istio/pkg/config/schema"
)

type IstioConfigStore struct {
	AuthorizationPoliciesStub        func(string) []model.Config
	authorizationPoliciesMutex       sync.RWMutex
	authorizationPoliciesArgsForCall []struct {
		arg1 string
	}
	authorizationPoliciesReturns struct {
		result1 []model.Config
	}
	authorizationPoliciesReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	ClusterRbacConfigStub        func() *model.Config
	clusterRbacConfigMutex       sync.RWMutex
	clusterRbacConfigArgsForCall []struct {
	}
	clusterRbacConfigReturns struct {
		result1 *model.Config
	}
	clusterRbacConfigReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	ConfigDescriptorStub        func() schema.Set
	configDescriptorMutex       sync.RWMutex
	configDescriptorArgsForCall []struct {
	}
	configDescriptorReturns struct {
		result1 schema.Set
	}
	configDescriptorReturnsOnCall map[int]struct {
		result1 schema.Set
	}
	CreateStub        func(model.Config) (string, error)
	createMutex       sync.RWMutex
	createArgsForCall []struct {
		arg1 model.Config
	}
	createReturns struct {
		result1 string
		result2 error
	}
	createReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	DeleteStub        func(string, string, string) error
	deleteMutex       sync.RWMutex
	deleteArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 string
	}
	deleteReturns struct {
		result1 error
	}
	deleteReturnsOnCall map[int]struct {
		result1 error
	}
	EnvoyFilterStub        func(labels.Collection) *model.Config
	envoyFilterMutex       sync.RWMutex
	envoyFilterArgsForCall []struct {
		arg1 labels.Collection
	}
	envoyFilterReturns struct {
		result1 *model.Config
	}
	envoyFilterReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	GatewaysStub        func(labels.Collection) []model.Config
	gatewaysMutex       sync.RWMutex
	gatewaysArgsForCall []struct {
		arg1 labels.Collection
	}
	gatewaysReturns struct {
		result1 []model.Config
	}
	gatewaysReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	GetStub        func(string, string, string) *model.Config
	getMutex       sync.RWMutex
	getArgsForCall []struct {
		arg1 string
		arg2 string
		arg3 string
	}
	getReturns struct {
		result1 *model.Config
	}
	getReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	GetResourceAtVersionStub        func(string, string) (string, error)
	getResourceAtVersionMutex       sync.RWMutex
	getResourceAtVersionArgsForCall []struct {
		arg1 string
		arg2 string
	}
	getResourceAtVersionReturns struct {
		result1 string
		result2 error
	}
	getResourceAtVersionReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	ListStub        func(string, string) ([]model.Config, error)
	listMutex       sync.RWMutex
	listArgsForCall []struct {
		arg1 string
		arg2 string
	}
	listReturns struct {
		result1 []model.Config
		result2 error
	}
	listReturnsOnCall map[int]struct {
		result1 []model.Config
		result2 error
	}
	QuotaSpecByDestinationStub        func(*model.ServiceInstance) []model.Config
	quotaSpecByDestinationMutex       sync.RWMutex
	quotaSpecByDestinationArgsForCall []struct {
		arg1 *model.ServiceInstance
	}
	quotaSpecByDestinationReturns struct {
		result1 []model.Config
	}
	quotaSpecByDestinationReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	RbacConfigStub        func() *model.Config
	rbacConfigMutex       sync.RWMutex
	rbacConfigArgsForCall []struct {
	}
	rbacConfigReturns struct {
		result1 *model.Config
	}
	rbacConfigReturnsOnCall map[int]struct {
		result1 *model.Config
	}
	ServiceEntriesStub        func() []model.Config
	serviceEntriesMutex       sync.RWMutex
	serviceEntriesArgsForCall []struct {
	}
	serviceEntriesReturns struct {
		result1 []model.Config
	}
	serviceEntriesReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	ServiceRoleBindingsStub        func(string) []model.Config
	serviceRoleBindingsMutex       sync.RWMutex
	serviceRoleBindingsArgsForCall []struct {
		arg1 string
	}
	serviceRoleBindingsReturns struct {
		result1 []model.Config
	}
	serviceRoleBindingsReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	ServiceRolesStub        func(string) []model.Config
	serviceRolesMutex       sync.RWMutex
	serviceRolesArgsForCall []struct {
		arg1 string
	}
	serviceRolesReturns struct {
		result1 []model.Config
	}
	serviceRolesReturnsOnCall map[int]struct {
		result1 []model.Config
	}
	UpdateStub        func(model.Config) (string, error)
	updateMutex       sync.RWMutex
	updateArgsForCall []struct {
		arg1 model.Config
	}
	updateReturns struct {
		result1 string
		result2 error
	}
	updateReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	VersionStub        func() string
	versionMutex       sync.RWMutex
	versionArgsForCall []struct {
	}
	versionReturns struct {
		result1 string
	}
	versionReturnsOnCall map[int]struct {
		result1 string
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *IstioConfigStore) AuthorizationPolicies(arg1 string) []model.Config {
	fake.authorizationPoliciesMutex.Lock()
	ret, specificReturn := fake.authorizationPoliciesReturnsOnCall[len(fake.authorizationPoliciesArgsForCall)]
	fake.authorizationPoliciesArgsForCall = append(fake.authorizationPoliciesArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("AuthorizationPolicies", []interface{}{arg1})
	fake.authorizationPoliciesMutex.Unlock()
	if fake.AuthorizationPoliciesStub != nil {
		return fake.AuthorizationPoliciesStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.authorizationPoliciesReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) AuthorizationPoliciesCallCount() int {
	fake.authorizationPoliciesMutex.RLock()
	defer fake.authorizationPoliciesMutex.RUnlock()
	return len(fake.authorizationPoliciesArgsForCall)
}

func (fake *IstioConfigStore) AuthorizationPoliciesCalls(stub func(string) []model.Config) {
	fake.authorizationPoliciesMutex.Lock()
	defer fake.authorizationPoliciesMutex.Unlock()
	fake.AuthorizationPoliciesStub = stub
}

func (fake *IstioConfigStore) AuthorizationPoliciesArgsForCall(i int) string {
	fake.authorizationPoliciesMutex.RLock()
	defer fake.authorizationPoliciesMutex.RUnlock()
	argsForCall := fake.authorizationPoliciesArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) AuthorizationPoliciesReturns(result1 []model.Config) {
	fake.authorizationPoliciesMutex.Lock()
	defer fake.authorizationPoliciesMutex.Unlock()
	fake.AuthorizationPoliciesStub = nil
	fake.authorizationPoliciesReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) AuthorizationPoliciesReturnsOnCall(i int, result1 []model.Config) {
	fake.authorizationPoliciesMutex.Lock()
	defer fake.authorizationPoliciesMutex.Unlock()
	fake.AuthorizationPoliciesStub = nil
	if fake.authorizationPoliciesReturnsOnCall == nil {
		fake.authorizationPoliciesReturnsOnCall = make(map[int]struct {
			result1 []model.Config
		})
	}
	fake.authorizationPoliciesReturnsOnCall[i] = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ClusterRbacConfig() *model.Config {
	fake.clusterRbacConfigMutex.Lock()
	ret, specificReturn := fake.clusterRbacConfigReturnsOnCall[len(fake.clusterRbacConfigArgsForCall)]
	fake.clusterRbacConfigArgsForCall = append(fake.clusterRbacConfigArgsForCall, struct {
	}{})
	fake.recordInvocation("ClusterRbacConfig", []interface{}{})
	fake.clusterRbacConfigMutex.Unlock()
	if fake.ClusterRbacConfigStub != nil {
		return fake.ClusterRbacConfigStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.clusterRbacConfigReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) ClusterRbacConfigCallCount() int {
	fake.clusterRbacConfigMutex.RLock()
	defer fake.clusterRbacConfigMutex.RUnlock()
	return len(fake.clusterRbacConfigArgsForCall)
}

func (fake *IstioConfigStore) ClusterRbacConfigCalls(stub func() *model.Config) {
	fake.clusterRbacConfigMutex.Lock()
	defer fake.clusterRbacConfigMutex.Unlock()
	fake.ClusterRbacConfigStub = stub
}

func (fake *IstioConfigStore) ClusterRbacConfigReturns(result1 *model.Config) {
	fake.clusterRbacConfigMutex.Lock()
	defer fake.clusterRbacConfigMutex.Unlock()
	fake.ClusterRbacConfigStub = nil
	fake.clusterRbacConfigReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) ClusterRbacConfigReturnsOnCall(i int, result1 *model.Config) {
	fake.clusterRbacConfigMutex.Lock()
	defer fake.clusterRbacConfigMutex.Unlock()
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

func (fake *IstioConfigStore) ConfigDescriptor() schema.Set {
	fake.configDescriptorMutex.Lock()
	ret, specificReturn := fake.configDescriptorReturnsOnCall[len(fake.configDescriptorArgsForCall)]
	fake.configDescriptorArgsForCall = append(fake.configDescriptorArgsForCall, struct {
	}{})
	fake.recordInvocation("ConfigDescriptor", []interface{}{})
	fake.configDescriptorMutex.Unlock()
	if fake.ConfigDescriptorStub != nil {
		return fake.ConfigDescriptorStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.configDescriptorReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) ConfigDescriptorCallCount() int {
	fake.configDescriptorMutex.RLock()
	defer fake.configDescriptorMutex.RUnlock()
	return len(fake.configDescriptorArgsForCall)
}

func (fake *IstioConfigStore) ConfigDescriptorCalls(stub func() schema.Set) {
	fake.configDescriptorMutex.Lock()
	defer fake.configDescriptorMutex.Unlock()
	fake.ConfigDescriptorStub = stub
}

func (fake *IstioConfigStore) ConfigDescriptorReturns(result1 schema.Set) {
	fake.configDescriptorMutex.Lock()
	defer fake.configDescriptorMutex.Unlock()
	fake.ConfigDescriptorStub = nil
	fake.configDescriptorReturns = struct {
		result1 schema.Set
	}{result1}
}

func (fake *IstioConfigStore) ConfigDescriptorReturnsOnCall(i int, result1 schema.Set) {
	fake.configDescriptorMutex.Lock()
	defer fake.configDescriptorMutex.Unlock()
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

func (fake *IstioConfigStore) Create(arg1 model.Config) (string, error) {
	fake.createMutex.Lock()
	ret, specificReturn := fake.createReturnsOnCall[len(fake.createArgsForCall)]
	fake.createArgsForCall = append(fake.createArgsForCall, struct {
		arg1 model.Config
	}{arg1})
	fake.recordInvocation("Create", []interface{}{arg1})
	fake.createMutex.Unlock()
	if fake.CreateStub != nil {
		return fake.CreateStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.createReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *IstioConfigStore) CreateCallCount() int {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return len(fake.createArgsForCall)
}

func (fake *IstioConfigStore) CreateCalls(stub func(model.Config) (string, error)) {
	fake.createMutex.Lock()
	defer fake.createMutex.Unlock()
	fake.CreateStub = stub
}

func (fake *IstioConfigStore) CreateArgsForCall(i int) model.Config {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	argsForCall := fake.createArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) CreateReturns(result1 string, result2 error) {
	fake.createMutex.Lock()
	defer fake.createMutex.Unlock()
	fake.CreateStub = nil
	fake.createReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) CreateReturnsOnCall(i int, result1 string, result2 error) {
	fake.createMutex.Lock()
	defer fake.createMutex.Unlock()
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

func (fake *IstioConfigStore) Delete(arg1 string, arg2 string, arg3 string) error {
	fake.deleteMutex.Lock()
	ret, specificReturn := fake.deleteReturnsOnCall[len(fake.deleteArgsForCall)]
	fake.deleteArgsForCall = append(fake.deleteArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 string
	}{arg1, arg2, arg3})
	fake.recordInvocation("Delete", []interface{}{arg1, arg2, arg3})
	fake.deleteMutex.Unlock()
	if fake.DeleteStub != nil {
		return fake.DeleteStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.deleteReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) DeleteCallCount() int {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return len(fake.deleteArgsForCall)
}

func (fake *IstioConfigStore) DeleteCalls(stub func(string, string, string) error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = stub
}

func (fake *IstioConfigStore) DeleteArgsForCall(i int) (string, string, string) {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	argsForCall := fake.deleteArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *IstioConfigStore) DeleteReturns(result1 error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
	fake.DeleteStub = nil
	fake.deleteReturns = struct {
		result1 error
	}{result1}
}

func (fake *IstioConfigStore) DeleteReturnsOnCall(i int, result1 error) {
	fake.deleteMutex.Lock()
	defer fake.deleteMutex.Unlock()
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

func (fake *IstioConfigStore) EnvoyFilter(arg1 labels.Collection) *model.Config {
	fake.envoyFilterMutex.Lock()
	ret, specificReturn := fake.envoyFilterReturnsOnCall[len(fake.envoyFilterArgsForCall)]
	fake.envoyFilterArgsForCall = append(fake.envoyFilterArgsForCall, struct {
		arg1 labels.Collection
	}{arg1})
	fake.recordInvocation("EnvoyFilter", []interface{}{arg1})
	fake.envoyFilterMutex.Unlock()
	if fake.EnvoyFilterStub != nil {
		return fake.EnvoyFilterStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.envoyFilterReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) EnvoyFilterCallCount() int {
	fake.envoyFilterMutex.RLock()
	defer fake.envoyFilterMutex.RUnlock()
	return len(fake.envoyFilterArgsForCall)
}

func (fake *IstioConfigStore) EnvoyFilterCalls(stub func(labels.Collection) *model.Config) {
	fake.envoyFilterMutex.Lock()
	defer fake.envoyFilterMutex.Unlock()
	fake.EnvoyFilterStub = stub
}

func (fake *IstioConfigStore) EnvoyFilterArgsForCall(i int) labels.Collection {
	fake.envoyFilterMutex.RLock()
	defer fake.envoyFilterMutex.RUnlock()
	argsForCall := fake.envoyFilterArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) EnvoyFilterReturns(result1 *model.Config) {
	fake.envoyFilterMutex.Lock()
	defer fake.envoyFilterMutex.Unlock()
	fake.EnvoyFilterStub = nil
	fake.envoyFilterReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) EnvoyFilterReturnsOnCall(i int, result1 *model.Config) {
	fake.envoyFilterMutex.Lock()
	defer fake.envoyFilterMutex.Unlock()
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

func (fake *IstioConfigStore) Gateways(arg1 labels.Collection) []model.Config {
	fake.gatewaysMutex.Lock()
	ret, specificReturn := fake.gatewaysReturnsOnCall[len(fake.gatewaysArgsForCall)]
	fake.gatewaysArgsForCall = append(fake.gatewaysArgsForCall, struct {
		arg1 labels.Collection
	}{arg1})
	fake.recordInvocation("Gateways", []interface{}{arg1})
	fake.gatewaysMutex.Unlock()
	if fake.GatewaysStub != nil {
		return fake.GatewaysStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.gatewaysReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) GatewaysCallCount() int {
	fake.gatewaysMutex.RLock()
	defer fake.gatewaysMutex.RUnlock()
	return len(fake.gatewaysArgsForCall)
}

func (fake *IstioConfigStore) GatewaysCalls(stub func(labels.Collection) []model.Config) {
	fake.gatewaysMutex.Lock()
	defer fake.gatewaysMutex.Unlock()
	fake.GatewaysStub = stub
}

func (fake *IstioConfigStore) GatewaysArgsForCall(i int) labels.Collection {
	fake.gatewaysMutex.RLock()
	defer fake.gatewaysMutex.RUnlock()
	argsForCall := fake.gatewaysArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) GatewaysReturns(result1 []model.Config) {
	fake.gatewaysMutex.Lock()
	defer fake.gatewaysMutex.Unlock()
	fake.GatewaysStub = nil
	fake.gatewaysReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) GatewaysReturnsOnCall(i int, result1 []model.Config) {
	fake.gatewaysMutex.Lock()
	defer fake.gatewaysMutex.Unlock()
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

func (fake *IstioConfigStore) Get(arg1 string, arg2 string, arg3 string) *model.Config {
	fake.getMutex.Lock()
	ret, specificReturn := fake.getReturnsOnCall[len(fake.getArgsForCall)]
	fake.getArgsForCall = append(fake.getArgsForCall, struct {
		arg1 string
		arg2 string
		arg3 string
	}{arg1, arg2, arg3})
	fake.recordInvocation("Get", []interface{}{arg1, arg2, arg3})
	fake.getMutex.Unlock()
	if fake.GetStub != nil {
		return fake.GetStub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.getReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *IstioConfigStore) GetCalls(stub func(string, string, string) *model.Config) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = stub
}

func (fake *IstioConfigStore) GetArgsForCall(i int) (string, string, string) {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	argsForCall := fake.getArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *IstioConfigStore) GetReturns(result1 *model.Config) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) GetReturnsOnCall(i int, result1 *model.Config) {
	fake.getMutex.Lock()
	defer fake.getMutex.Unlock()
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

func (fake *IstioConfigStore) GetResourceAtVersion(arg1 string, arg2 string) (string, error) {
	fake.getResourceAtVersionMutex.Lock()
	ret, specificReturn := fake.getResourceAtVersionReturnsOnCall[len(fake.getResourceAtVersionArgsForCall)]
	fake.getResourceAtVersionArgsForCall = append(fake.getResourceAtVersionArgsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.recordInvocation("GetResourceAtVersion", []interface{}{arg1, arg2})
	fake.getResourceAtVersionMutex.Unlock()
	if fake.GetResourceAtVersionStub != nil {
		return fake.GetResourceAtVersionStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.getResourceAtVersionReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *IstioConfigStore) GetResourceAtVersionCallCount() int {
	fake.getResourceAtVersionMutex.RLock()
	defer fake.getResourceAtVersionMutex.RUnlock()
	return len(fake.getResourceAtVersionArgsForCall)
}

func (fake *IstioConfigStore) GetResourceAtVersionCalls(stub func(string, string) (string, error)) {
	fake.getResourceAtVersionMutex.Lock()
	defer fake.getResourceAtVersionMutex.Unlock()
	fake.GetResourceAtVersionStub = stub
}

func (fake *IstioConfigStore) GetResourceAtVersionArgsForCall(i int) (string, string) {
	fake.getResourceAtVersionMutex.RLock()
	defer fake.getResourceAtVersionMutex.RUnlock()
	argsForCall := fake.getResourceAtVersionArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *IstioConfigStore) GetResourceAtVersionReturns(result1 string, result2 error) {
	fake.getResourceAtVersionMutex.Lock()
	defer fake.getResourceAtVersionMutex.Unlock()
	fake.GetResourceAtVersionStub = nil
	fake.getResourceAtVersionReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) GetResourceAtVersionReturnsOnCall(i int, result1 string, result2 error) {
	fake.getResourceAtVersionMutex.Lock()
	defer fake.getResourceAtVersionMutex.Unlock()
	fake.GetResourceAtVersionStub = nil
	if fake.getResourceAtVersionReturnsOnCall == nil {
		fake.getResourceAtVersionReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.getResourceAtVersionReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) List(arg1 string, arg2 string) ([]model.Config, error) {
	fake.listMutex.Lock()
	ret, specificReturn := fake.listReturnsOnCall[len(fake.listArgsForCall)]
	fake.listArgsForCall = append(fake.listArgsForCall, struct {
		arg1 string
		arg2 string
	}{arg1, arg2})
	fake.recordInvocation("List", []interface{}{arg1, arg2})
	fake.listMutex.Unlock()
	if fake.ListStub != nil {
		return fake.ListStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.listReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *IstioConfigStore) ListCallCount() int {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return len(fake.listArgsForCall)
}

func (fake *IstioConfigStore) ListCalls(stub func(string, string) ([]model.Config, error)) {
	fake.listMutex.Lock()
	defer fake.listMutex.Unlock()
	fake.ListStub = stub
}

func (fake *IstioConfigStore) ListArgsForCall(i int) (string, string) {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	argsForCall := fake.listArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *IstioConfigStore) ListReturns(result1 []model.Config, result2 error) {
	fake.listMutex.Lock()
	defer fake.listMutex.Unlock()
	fake.ListStub = nil
	fake.listReturns = struct {
		result1 []model.Config
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) ListReturnsOnCall(i int, result1 []model.Config, result2 error) {
	fake.listMutex.Lock()
	defer fake.listMutex.Unlock()
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

func (fake *IstioConfigStore) QuotaSpecByDestination(arg1 *model.ServiceInstance) []model.Config {
	fake.quotaSpecByDestinationMutex.Lock()
	ret, specificReturn := fake.quotaSpecByDestinationReturnsOnCall[len(fake.quotaSpecByDestinationArgsForCall)]
	fake.quotaSpecByDestinationArgsForCall = append(fake.quotaSpecByDestinationArgsForCall, struct {
		arg1 *model.ServiceInstance
	}{arg1})
	fake.recordInvocation("QuotaSpecByDestination", []interface{}{arg1})
	fake.quotaSpecByDestinationMutex.Unlock()
	if fake.QuotaSpecByDestinationStub != nil {
		return fake.QuotaSpecByDestinationStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.quotaSpecByDestinationReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) QuotaSpecByDestinationCallCount() int {
	fake.quotaSpecByDestinationMutex.RLock()
	defer fake.quotaSpecByDestinationMutex.RUnlock()
	return len(fake.quotaSpecByDestinationArgsForCall)
}

func (fake *IstioConfigStore) QuotaSpecByDestinationCalls(stub func(*model.ServiceInstance) []model.Config) {
	fake.quotaSpecByDestinationMutex.Lock()
	defer fake.quotaSpecByDestinationMutex.Unlock()
	fake.QuotaSpecByDestinationStub = stub
}

func (fake *IstioConfigStore) QuotaSpecByDestinationArgsForCall(i int) *model.ServiceInstance {
	fake.quotaSpecByDestinationMutex.RLock()
	defer fake.quotaSpecByDestinationMutex.RUnlock()
	argsForCall := fake.quotaSpecByDestinationArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) QuotaSpecByDestinationReturns(result1 []model.Config) {
	fake.quotaSpecByDestinationMutex.Lock()
	defer fake.quotaSpecByDestinationMutex.Unlock()
	fake.QuotaSpecByDestinationStub = nil
	fake.quotaSpecByDestinationReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) QuotaSpecByDestinationReturnsOnCall(i int, result1 []model.Config) {
	fake.quotaSpecByDestinationMutex.Lock()
	defer fake.quotaSpecByDestinationMutex.Unlock()
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

func (fake *IstioConfigStore) RbacConfig() *model.Config {
	fake.rbacConfigMutex.Lock()
	ret, specificReturn := fake.rbacConfigReturnsOnCall[len(fake.rbacConfigArgsForCall)]
	fake.rbacConfigArgsForCall = append(fake.rbacConfigArgsForCall, struct {
	}{})
	fake.recordInvocation("RbacConfig", []interface{}{})
	fake.rbacConfigMutex.Unlock()
	if fake.RbacConfigStub != nil {
		return fake.RbacConfigStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.rbacConfigReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) RbacConfigCallCount() int {
	fake.rbacConfigMutex.RLock()
	defer fake.rbacConfigMutex.RUnlock()
	return len(fake.rbacConfigArgsForCall)
}

func (fake *IstioConfigStore) RbacConfigCalls(stub func() *model.Config) {
	fake.rbacConfigMutex.Lock()
	defer fake.rbacConfigMutex.Unlock()
	fake.RbacConfigStub = stub
}

func (fake *IstioConfigStore) RbacConfigReturns(result1 *model.Config) {
	fake.rbacConfigMutex.Lock()
	defer fake.rbacConfigMutex.Unlock()
	fake.RbacConfigStub = nil
	fake.rbacConfigReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *IstioConfigStore) RbacConfigReturnsOnCall(i int, result1 *model.Config) {
	fake.rbacConfigMutex.Lock()
	defer fake.rbacConfigMutex.Unlock()
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

func (fake *IstioConfigStore) ServiceEntries() []model.Config {
	fake.serviceEntriesMutex.Lock()
	ret, specificReturn := fake.serviceEntriesReturnsOnCall[len(fake.serviceEntriesArgsForCall)]
	fake.serviceEntriesArgsForCall = append(fake.serviceEntriesArgsForCall, struct {
	}{})
	fake.recordInvocation("ServiceEntries", []interface{}{})
	fake.serviceEntriesMutex.Unlock()
	if fake.ServiceEntriesStub != nil {
		return fake.ServiceEntriesStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.serviceEntriesReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) ServiceEntriesCallCount() int {
	fake.serviceEntriesMutex.RLock()
	defer fake.serviceEntriesMutex.RUnlock()
	return len(fake.serviceEntriesArgsForCall)
}

func (fake *IstioConfigStore) ServiceEntriesCalls(stub func() []model.Config) {
	fake.serviceEntriesMutex.Lock()
	defer fake.serviceEntriesMutex.Unlock()
	fake.ServiceEntriesStub = stub
}

func (fake *IstioConfigStore) ServiceEntriesReturns(result1 []model.Config) {
	fake.serviceEntriesMutex.Lock()
	defer fake.serviceEntriesMutex.Unlock()
	fake.ServiceEntriesStub = nil
	fake.serviceEntriesReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceEntriesReturnsOnCall(i int, result1 []model.Config) {
	fake.serviceEntriesMutex.Lock()
	defer fake.serviceEntriesMutex.Unlock()
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

func (fake *IstioConfigStore) ServiceRoleBindings(arg1 string) []model.Config {
	fake.serviceRoleBindingsMutex.Lock()
	ret, specificReturn := fake.serviceRoleBindingsReturnsOnCall[len(fake.serviceRoleBindingsArgsForCall)]
	fake.serviceRoleBindingsArgsForCall = append(fake.serviceRoleBindingsArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("ServiceRoleBindings", []interface{}{arg1})
	fake.serviceRoleBindingsMutex.Unlock()
	if fake.ServiceRoleBindingsStub != nil {
		return fake.ServiceRoleBindingsStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.serviceRoleBindingsReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) ServiceRoleBindingsCallCount() int {
	fake.serviceRoleBindingsMutex.RLock()
	defer fake.serviceRoleBindingsMutex.RUnlock()
	return len(fake.serviceRoleBindingsArgsForCall)
}

func (fake *IstioConfigStore) ServiceRoleBindingsCalls(stub func(string) []model.Config) {
	fake.serviceRoleBindingsMutex.Lock()
	defer fake.serviceRoleBindingsMutex.Unlock()
	fake.ServiceRoleBindingsStub = stub
}

func (fake *IstioConfigStore) ServiceRoleBindingsArgsForCall(i int) string {
	fake.serviceRoleBindingsMutex.RLock()
	defer fake.serviceRoleBindingsMutex.RUnlock()
	argsForCall := fake.serviceRoleBindingsArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) ServiceRoleBindingsReturns(result1 []model.Config) {
	fake.serviceRoleBindingsMutex.Lock()
	defer fake.serviceRoleBindingsMutex.Unlock()
	fake.ServiceRoleBindingsStub = nil
	fake.serviceRoleBindingsReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceRoleBindingsReturnsOnCall(i int, result1 []model.Config) {
	fake.serviceRoleBindingsMutex.Lock()
	defer fake.serviceRoleBindingsMutex.Unlock()
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

func (fake *IstioConfigStore) ServiceRoles(arg1 string) []model.Config {
	fake.serviceRolesMutex.Lock()
	ret, specificReturn := fake.serviceRolesReturnsOnCall[len(fake.serviceRolesArgsForCall)]
	fake.serviceRolesArgsForCall = append(fake.serviceRolesArgsForCall, struct {
		arg1 string
	}{arg1})
	fake.recordInvocation("ServiceRoles", []interface{}{arg1})
	fake.serviceRolesMutex.Unlock()
	if fake.ServiceRolesStub != nil {
		return fake.ServiceRolesStub(arg1)
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.serviceRolesReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) ServiceRolesCallCount() int {
	fake.serviceRolesMutex.RLock()
	defer fake.serviceRolesMutex.RUnlock()
	return len(fake.serviceRolesArgsForCall)
}

func (fake *IstioConfigStore) ServiceRolesCalls(stub func(string) []model.Config) {
	fake.serviceRolesMutex.Lock()
	defer fake.serviceRolesMutex.Unlock()
	fake.ServiceRolesStub = stub
}

func (fake *IstioConfigStore) ServiceRolesArgsForCall(i int) string {
	fake.serviceRolesMutex.RLock()
	defer fake.serviceRolesMutex.RUnlock()
	argsForCall := fake.serviceRolesArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) ServiceRolesReturns(result1 []model.Config) {
	fake.serviceRolesMutex.Lock()
	defer fake.serviceRolesMutex.Unlock()
	fake.ServiceRolesStub = nil
	fake.serviceRolesReturns = struct {
		result1 []model.Config
	}{result1}
}

func (fake *IstioConfigStore) ServiceRolesReturnsOnCall(i int, result1 []model.Config) {
	fake.serviceRolesMutex.Lock()
	defer fake.serviceRolesMutex.Unlock()
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

func (fake *IstioConfigStore) Update(arg1 model.Config) (string, error) {
	fake.updateMutex.Lock()
	ret, specificReturn := fake.updateReturnsOnCall[len(fake.updateArgsForCall)]
	fake.updateArgsForCall = append(fake.updateArgsForCall, struct {
		arg1 model.Config
	}{arg1})
	fake.recordInvocation("Update", []interface{}{arg1})
	fake.updateMutex.Unlock()
	if fake.UpdateStub != nil {
		return fake.UpdateStub(arg1)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.updateReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *IstioConfigStore) UpdateCallCount() int {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	return len(fake.updateArgsForCall)
}

func (fake *IstioConfigStore) UpdateCalls(stub func(model.Config) (string, error)) {
	fake.updateMutex.Lock()
	defer fake.updateMutex.Unlock()
	fake.UpdateStub = stub
}

func (fake *IstioConfigStore) UpdateArgsForCall(i int) model.Config {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	argsForCall := fake.updateArgsForCall[i]
	return argsForCall.arg1
}

func (fake *IstioConfigStore) UpdateReturns(result1 string, result2 error) {
	fake.updateMutex.Lock()
	defer fake.updateMutex.Unlock()
	fake.UpdateStub = nil
	fake.updateReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *IstioConfigStore) UpdateReturnsOnCall(i int, result1 string, result2 error) {
	fake.updateMutex.Lock()
	defer fake.updateMutex.Unlock()
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

func (fake *IstioConfigStore) Version() string {
	fake.versionMutex.Lock()
	ret, specificReturn := fake.versionReturnsOnCall[len(fake.versionArgsForCall)]
	fake.versionArgsForCall = append(fake.versionArgsForCall, struct {
	}{})
	fake.recordInvocation("Version", []interface{}{})
	fake.versionMutex.Unlock()
	if fake.VersionStub != nil {
		return fake.VersionStub()
	}
	if specificReturn {
		return ret.result1
	}
	fakeReturns := fake.versionReturns
	return fakeReturns.result1
}

func (fake *IstioConfigStore) VersionCallCount() int {
	fake.versionMutex.RLock()
	defer fake.versionMutex.RUnlock()
	return len(fake.versionArgsForCall)
}

func (fake *IstioConfigStore) VersionCalls(stub func() string) {
	fake.versionMutex.Lock()
	defer fake.versionMutex.Unlock()
	fake.VersionStub = stub
}

func (fake *IstioConfigStore) VersionReturns(result1 string) {
	fake.versionMutex.Lock()
	defer fake.versionMutex.Unlock()
	fake.VersionStub = nil
	fake.versionReturns = struct {
		result1 string
	}{result1}
}

func (fake *IstioConfigStore) VersionReturnsOnCall(i int, result1 string) {
	fake.versionMutex.Lock()
	defer fake.versionMutex.Unlock()
	fake.VersionStub = nil
	if fake.versionReturnsOnCall == nil {
		fake.versionReturnsOnCall = make(map[int]struct {
			result1 string
		})
	}
	fake.versionReturnsOnCall[i] = struct {
		result1 string
	}{result1}
}

func (fake *IstioConfigStore) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.authorizationPoliciesMutex.RLock()
	defer fake.authorizationPoliciesMutex.RUnlock()
	fake.clusterRbacConfigMutex.RLock()
	defer fake.clusterRbacConfigMutex.RUnlock()
	fake.configDescriptorMutex.RLock()
	defer fake.configDescriptorMutex.RUnlock()
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	fake.envoyFilterMutex.RLock()
	defer fake.envoyFilterMutex.RUnlock()
	fake.gatewaysMutex.RLock()
	defer fake.gatewaysMutex.RUnlock()
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	fake.getResourceAtVersionMutex.RLock()
	defer fake.getResourceAtVersionMutex.RUnlock()
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	fake.quotaSpecByDestinationMutex.RLock()
	defer fake.quotaSpecByDestinationMutex.RUnlock()
	fake.rbacConfigMutex.RLock()
	defer fake.rbacConfigMutex.RUnlock()
	fake.serviceEntriesMutex.RLock()
	defer fake.serviceEntriesMutex.RUnlock()
	fake.serviceRoleBindingsMutex.RLock()
	defer fake.serviceRoleBindingsMutex.RUnlock()
	fake.serviceRolesMutex.RLock()
	defer fake.serviceRolesMutex.RUnlock()
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	fake.versionMutex.RLock()
	defer fake.versionMutex.RUnlock()
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
