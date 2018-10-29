// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"istio.io/istio/pilot/pkg/model"
)

type ConfigStoreCache struct {
	ConfigDescriptorStub        func() model.ConfigDescriptor
	configDescriptorMutex       sync.RWMutex
	configDescriptorArgsForCall []struct{}
	configDescriptorReturns     struct {
		result1 model.ConfigDescriptor
	}
	configDescriptorReturnsOnCall map[int]struct {
		result1 model.ConfigDescriptor
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
	RegisterEventHandlerStub        func(typ string, handler func(model.Config, model.Event))
	registerEventHandlerMutex       sync.RWMutex
	registerEventHandlerArgsForCall []struct {
		typ     string
		handler func(model.Config, model.Event)
	}
	RunStub        func(stop <-chan struct{})
	runMutex       sync.RWMutex
	runArgsForCall []struct {
		stop <-chan struct{}
	}
	HasSyncedStub        func() bool
	hasSyncedMutex       sync.RWMutex
	hasSyncedArgsForCall []struct{}
	hasSyncedReturns     struct {
		result1 bool
	}
	hasSyncedReturnsOnCall map[int]struct {
		result1 bool
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *ConfigStoreCache) ConfigDescriptor() model.ConfigDescriptor {
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

func (fake *ConfigStoreCache) ConfigDescriptorCallCount() int {
	fake.configDescriptorMutex.RLock()
	defer fake.configDescriptorMutex.RUnlock()
	return len(fake.configDescriptorArgsForCall)
}

func (fake *ConfigStoreCache) ConfigDescriptorReturns(result1 model.ConfigDescriptor) {
	fake.ConfigDescriptorStub = nil
	fake.configDescriptorReturns = struct {
		result1 model.ConfigDescriptor
	}{result1}
}

func (fake *ConfigStoreCache) ConfigDescriptorReturnsOnCall(i int, result1 model.ConfigDescriptor) {
	fake.ConfigDescriptorStub = nil
	if fake.configDescriptorReturnsOnCall == nil {
		fake.configDescriptorReturnsOnCall = make(map[int]struct {
			result1 model.ConfigDescriptor
		})
	}
	fake.configDescriptorReturnsOnCall[i] = struct {
		result1 model.ConfigDescriptor
	}{result1}
}

func (fake *ConfigStoreCache) Get(typ string, name string, namespace string) *model.Config {
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

func (fake *ConfigStoreCache) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *ConfigStoreCache) GetArgsForCall(i int) (string, string, string) {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return fake.getArgsForCall[i].typ, fake.getArgsForCall[i].name, fake.getArgsForCall[i].namespace
}

func (fake *ConfigStoreCache) GetReturns(result1 *model.Config) {
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 *model.Config
	}{result1}
}

func (fake *ConfigStoreCache) GetReturnsOnCall(i int, result1 *model.Config) {
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

func (fake *ConfigStoreCache) List(typ string, namespace string) ([]model.Config, error) {
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

func (fake *ConfigStoreCache) ListCallCount() int {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return len(fake.listArgsForCall)
}

func (fake *ConfigStoreCache) ListArgsForCall(i int) (string, string) {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return fake.listArgsForCall[i].typ, fake.listArgsForCall[i].namespace
}

func (fake *ConfigStoreCache) ListReturns(result1 []model.Config, result2 error) {
	fake.ListStub = nil
	fake.listReturns = struct {
		result1 []model.Config
		result2 error
	}{result1, result2}
}

func (fake *ConfigStoreCache) ListReturnsOnCall(i int, result1 []model.Config, result2 error) {
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

func (fake *ConfigStoreCache) Create(config model.Config) (revision string, err error) {
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

func (fake *ConfigStoreCache) CreateCallCount() int {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return len(fake.createArgsForCall)
}

func (fake *ConfigStoreCache) CreateArgsForCall(i int) model.Config {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return fake.createArgsForCall[i].config
}

func (fake *ConfigStoreCache) CreateReturns(result1 string, result2 error) {
	fake.CreateStub = nil
	fake.createReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *ConfigStoreCache) CreateReturnsOnCall(i int, result1 string, result2 error) {
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

func (fake *ConfigStoreCache) Update(config model.Config) (newRevision string, err error) {
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

func (fake *ConfigStoreCache) UpdateCallCount() int {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	return len(fake.updateArgsForCall)
}

func (fake *ConfigStoreCache) UpdateArgsForCall(i int) model.Config {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	return fake.updateArgsForCall[i].config
}

func (fake *ConfigStoreCache) UpdateReturns(result1 string, result2 error) {
	fake.UpdateStub = nil
	fake.updateReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *ConfigStoreCache) UpdateReturnsOnCall(i int, result1 string, result2 error) {
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

func (fake *ConfigStoreCache) Delete(typ string, name string, namespace string) error {
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

func (fake *ConfigStoreCache) DeleteCallCount() int {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return len(fake.deleteArgsForCall)
}

func (fake *ConfigStoreCache) DeleteArgsForCall(i int) (string, string, string) {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return fake.deleteArgsForCall[i].typ, fake.deleteArgsForCall[i].name, fake.deleteArgsForCall[i].namespace
}

func (fake *ConfigStoreCache) DeleteReturns(result1 error) {
	fake.DeleteStub = nil
	fake.deleteReturns = struct {
		result1 error
	}{result1}
}

func (fake *ConfigStoreCache) DeleteReturnsOnCall(i int, result1 error) {
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

func (fake *ConfigStoreCache) RegisterEventHandler(typ string, handler func(model.Config, model.Event)) {
	fake.registerEventHandlerMutex.Lock()
	fake.registerEventHandlerArgsForCall = append(fake.registerEventHandlerArgsForCall, struct {
		typ     string
		handler func(model.Config, model.Event)
	}{typ, handler})
	fake.recordInvocation("RegisterEventHandler", []interface{}{typ, handler})
	fake.registerEventHandlerMutex.Unlock()
	if fake.RegisterEventHandlerStub != nil {
		fake.RegisterEventHandlerStub(typ, handler)
	}
}

func (fake *ConfigStoreCache) RegisterEventHandlerCallCount() int {
	fake.registerEventHandlerMutex.RLock()
	defer fake.registerEventHandlerMutex.RUnlock()
	return len(fake.registerEventHandlerArgsForCall)
}

func (fake *ConfigStoreCache) RegisterEventHandlerArgsForCall(i int) (string, func(model.Config, model.Event)) {
	fake.registerEventHandlerMutex.RLock()
	defer fake.registerEventHandlerMutex.RUnlock()
	return fake.registerEventHandlerArgsForCall[i].typ, fake.registerEventHandlerArgsForCall[i].handler
}

func (fake *ConfigStoreCache) Run(stop <-chan struct{}) {
	fake.runMutex.Lock()
	fake.runArgsForCall = append(fake.runArgsForCall, struct {
		stop <-chan struct{}
	}{stop})
	fake.recordInvocation("Run", []interface{}{stop})
	fake.runMutex.Unlock()
	if fake.RunStub != nil {
		fake.RunStub(stop)
	}
}

func (fake *ConfigStoreCache) RunCallCount() int {
	fake.runMutex.RLock()
	defer fake.runMutex.RUnlock()
	return len(fake.runArgsForCall)
}

func (fake *ConfigStoreCache) RunArgsForCall(i int) <-chan struct{} {
	fake.runMutex.RLock()
	defer fake.runMutex.RUnlock()
	return fake.runArgsForCall[i].stop
}

func (fake *ConfigStoreCache) HasSynced() bool {
	fake.hasSyncedMutex.Lock()
	ret, specificReturn := fake.hasSyncedReturnsOnCall[len(fake.hasSyncedArgsForCall)]
	fake.hasSyncedArgsForCall = append(fake.hasSyncedArgsForCall, struct{}{})
	fake.recordInvocation("HasSynced", []interface{}{})
	fake.hasSyncedMutex.Unlock()
	if fake.HasSyncedStub != nil {
		return fake.HasSyncedStub()
	}
	if specificReturn {
		return ret.result1
	}
	return fake.hasSyncedReturns.result1
}

func (fake *ConfigStoreCache) HasSyncedCallCount() int {
	fake.hasSyncedMutex.RLock()
	defer fake.hasSyncedMutex.RUnlock()
	return len(fake.hasSyncedArgsForCall)
}

func (fake *ConfigStoreCache) HasSyncedReturns(result1 bool) {
	fake.HasSyncedStub = nil
	fake.hasSyncedReturns = struct {
		result1 bool
	}{result1}
}

func (fake *ConfigStoreCache) HasSyncedReturnsOnCall(i int, result1 bool) {
	fake.HasSyncedStub = nil
	if fake.hasSyncedReturnsOnCall == nil {
		fake.hasSyncedReturnsOnCall = make(map[int]struct {
			result1 bool
		})
	}
	fake.hasSyncedReturnsOnCall[i] = struct {
		result1 bool
	}{result1}
}

func (fake *ConfigStoreCache) Invocations() map[string][][]interface{} {
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
	fake.registerEventHandlerMutex.RLock()
	defer fake.registerEventHandlerMutex.RUnlock()
	fake.runMutex.RLock()
	defer fake.runMutex.RUnlock()
	fake.hasSyncedMutex.RLock()
	defer fake.hasSyncedMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *ConfigStoreCache) recordInvocation(key string, args []interface{}) {
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

var _ model.ConfigStoreCache = new(ConfigStoreCache)
