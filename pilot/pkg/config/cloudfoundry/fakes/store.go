// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"

	"istio.io/istio/pilot/pkg/model"
)

type Store struct {
	ConfigDescriptorStub        func() model.ConfigDescriptor
	configDescriptorMutex       sync.RWMutex
	configDescriptorArgsForCall []struct{}
	configDescriptorReturns     struct {
		result1 model.ConfigDescriptor
	}
	configDescriptorReturnsOnCall map[int]struct {
		result1 model.ConfigDescriptor
	}
	GetStub        func(typ, name, namespace string) (config *model.Config, exists bool)
	getMutex       sync.RWMutex
	getArgsForCall []struct {
		typ       string
		name      string
		namespace string
	}
	getReturns struct {
		result1 *model.Config
		result2 bool
	}
	getReturnsOnCall map[int]struct {
		result1 *model.Config
		result2 bool
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
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Store) ConfigDescriptor() model.ConfigDescriptor {
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

func (fake *Store) ConfigDescriptorCallCount() int {
	fake.configDescriptorMutex.RLock()
	defer fake.configDescriptorMutex.RUnlock()
	return len(fake.configDescriptorArgsForCall)
}

func (fake *Store) ConfigDescriptorReturns(result1 model.ConfigDescriptor) {
	fake.ConfigDescriptorStub = nil
	fake.configDescriptorReturns = struct {
		result1 model.ConfigDescriptor
	}{result1}
}

func (fake *Store) ConfigDescriptorReturnsOnCall(i int, result1 model.ConfigDescriptor) {
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

func (fake *Store) Get(typ string, name string, namespace string) (config *model.Config, exists bool) {
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
		return ret.result1, ret.result2
	}
	return fake.getReturns.result1, fake.getReturns.result2
}

func (fake *Store) GetCallCount() int {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return len(fake.getArgsForCall)
}

func (fake *Store) GetArgsForCall(i int) (string, string, string) {
	fake.getMutex.RLock()
	defer fake.getMutex.RUnlock()
	return fake.getArgsForCall[i].typ, fake.getArgsForCall[i].name, fake.getArgsForCall[i].namespace
}

func (fake *Store) GetReturns(result1 *model.Config, result2 bool) {
	fake.GetStub = nil
	fake.getReturns = struct {
		result1 *model.Config
		result2 bool
	}{result1, result2}
}

func (fake *Store) GetReturnsOnCall(i int, result1 *model.Config, result2 bool) {
	fake.GetStub = nil
	if fake.getReturnsOnCall == nil {
		fake.getReturnsOnCall = make(map[int]struct {
			result1 *model.Config
			result2 bool
		})
	}
	fake.getReturnsOnCall[i] = struct {
		result1 *model.Config
		result2 bool
	}{result1, result2}
}

func (fake *Store) List(typ string, namespace string) ([]model.Config, error) {
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

func (fake *Store) ListCallCount() int {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return len(fake.listArgsForCall)
}

func (fake *Store) ListArgsForCall(i int) (string, string) {
	fake.listMutex.RLock()
	defer fake.listMutex.RUnlock()
	return fake.listArgsForCall[i].typ, fake.listArgsForCall[i].namespace
}

func (fake *Store) ListReturns(result1 []model.Config, result2 error) {
	fake.ListStub = nil
	fake.listReturns = struct {
		result1 []model.Config
		result2 error
	}{result1, result2}
}

func (fake *Store) ListReturnsOnCall(i int, result1 []model.Config, result2 error) {
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

func (fake *Store) Create(config model.Config) (revision string, err error) {
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

func (fake *Store) CreateCallCount() int {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return len(fake.createArgsForCall)
}

func (fake *Store) CreateArgsForCall(i int) model.Config {
	fake.createMutex.RLock()
	defer fake.createMutex.RUnlock()
	return fake.createArgsForCall[i].config
}

func (fake *Store) CreateReturns(result1 string, result2 error) {
	fake.CreateStub = nil
	fake.createReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Store) CreateReturnsOnCall(i int, result1 string, result2 error) {
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

func (fake *Store) Update(config model.Config) (newRevision string, err error) {
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

func (fake *Store) UpdateCallCount() int {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	return len(fake.updateArgsForCall)
}

func (fake *Store) UpdateArgsForCall(i int) model.Config {
	fake.updateMutex.RLock()
	defer fake.updateMutex.RUnlock()
	return fake.updateArgsForCall[i].config
}

func (fake *Store) UpdateReturns(result1 string, result2 error) {
	fake.UpdateStub = nil
	fake.updateReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *Store) UpdateReturnsOnCall(i int, result1 string, result2 error) {
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

func (fake *Store) Delete(typ string, name string, namespace string) error {
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

func (fake *Store) DeleteCallCount() int {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return len(fake.deleteArgsForCall)
}

func (fake *Store) DeleteArgsForCall(i int) (string, string, string) {
	fake.deleteMutex.RLock()
	defer fake.deleteMutex.RUnlock()
	return fake.deleteArgsForCall[i].typ, fake.deleteArgsForCall[i].name, fake.deleteArgsForCall[i].namespace
}

func (fake *Store) DeleteReturns(result1 error) {
	fake.DeleteStub = nil
	fake.deleteReturns = struct {
		result1 error
	}{result1}
}

func (fake *Store) DeleteReturnsOnCall(i int, result1 error) {
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

func (fake *Store) Invocations() map[string][][]interface{} {
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
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Store) recordInvocation(key string, args []interface{}) {
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

var _ model.ConfigStore = new(Store)
