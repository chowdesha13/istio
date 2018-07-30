// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	"sync"
)

type Logger struct {
	InfoaStub        func(args ...interface{})
	infoaMutex       sync.RWMutex
	infoaArgsForCall []struct {
		args []interface{}
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *Logger) Infoa(args ...interface{}) {
	fake.infoaMutex.Lock()
	fake.infoaArgsForCall = append(fake.infoaArgsForCall, struct {
		args []interface{}
	}{args})
	fake.recordInvocation("Infoa", []interface{}{args})
	fake.infoaMutex.Unlock()
	if fake.InfoaStub != nil {
		fake.InfoaStub(args...)
	}
}

func (fake *Logger) InfoaCallCount() int {
	fake.infoaMutex.RLock()
	defer fake.infoaMutex.RUnlock()
	return len(fake.infoaArgsForCall)
}

func (fake *Logger) InfoaArgsForCall(i int) []interface{} {
	fake.infoaMutex.RLock()
	defer fake.infoaMutex.RUnlock()
	return fake.infoaArgsForCall[i].args
}

func (fake *Logger) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.infoaMutex.RLock()
	defer fake.infoaMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *Logger) recordInvocation(key string, args []interface{}) {
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
