// Copyright 2016 Istio Authors
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

package aspect

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	rpc "github.com/googleapis/googleapis/google/rpc"

	dpb "istio.io/api/mixer/v1/config/descriptor"
	"istio.io/mixer/pkg/adapter"
	aconfig "istio.io/mixer/pkg/aspect/config"
	"istio.io/mixer/pkg/aspect/test"
	"istio.io/mixer/pkg/config"
	cpb "istio.io/mixer/pkg/config/proto"
	"istio.io/mixer/pkg/expr"
)

func TestListsManager(t *testing.T) {
	df := test.NewDescriptorFinder(map[string]interface{}{
		"source.ip": &dpb.AttributeDescriptor{Name: "source.ip", ValueType: dpb.STRING},
	})

	lm := newListsManager()
	if lm.Kind() != config.ListsKind {
		t.Errorf("m.Kind() = %s wanted %s", lm.Kind(), config.ListsKind)
	}
	if err := lm.ValidateConfig(lm.DefaultConfig(), expr.NewCEXLEvaluator(), df); err != nil {
		t.Errorf("ValidateConfig(DefaultConfig()) produced an error: %v", err)
	}
	if err := lm.ValidateConfig(&aconfig.ListsParams{}, expr.NewCEXLEvaluator(), df); err == nil {
		t.Error("ValidateConfig(ListsParams{}) should produce an error.")
	}
}

func TestListsManager_ValidateConfig(t *testing.T) {
	df := test.NewDescriptorFinder(map[string]interface{}{
		"string": &dpb.AttributeDescriptor{Name: "string", ValueType: dpb.STRING},
		"int64":  &dpb.AttributeDescriptor{Name: "int64", ValueType: dpb.INT64},
	})

	tests := []struct {
		name string
		cfg  *aconfig.ListsParams
		err  string
	}{
		{"valid", &aconfig.ListsParams{CheckExpression: "string"}, ""},
		{"empty config", &aconfig.ListsParams{}, "no expression provided"},
		{"invalid expression", &aconfig.ListsParams{CheckExpression: "string |"}, "error type checking expression"},
		{"wrong type", &aconfig.ListsParams{CheckExpression: "int64"}, "expected type STRING"},
	}

	for idx, tt := range tests {
		t.Run(fmt.Sprintf("[%d] %s", idx, tt.name), func(t *testing.T) {
			if errs := (&listsManager{}).ValidateConfig(tt.cfg, expr.NewCEXLEvaluator(), df); errs != nil || tt.err != "" {
				if tt.err == "" {
					t.Fatalf("ValidateConfig(tt.cfg, tt.v, tt.df) = '%s', wanted no err", errs.Error())
				} else if !strings.Contains(errs.Error(), tt.err) {
					t.Fatalf("Expected errors containing the string '%s', actual: '%s'", tt.err, errs.Error())
				}
			}
		})
	}
}

type testListsBuilder struct {
	adapter.DefaultBuilder
	returnErr bool
}

func newListsBuilder(returnErr bool) testListsBuilder {
	return testListsBuilder{adapter.NewDefaultBuilder("test", "test", nil), returnErr}
}

func (t testListsBuilder) NewListsAspect(env adapter.Env, c adapter.Config) (adapter.ListsAspect, error) {
	if t.returnErr {
		return nil, errors.New("error")
	}
	return &testList{}, nil
}

func TestListsManager_NewCheckExecutor(t *testing.T) {
	defaultCfg := &cpb.Combined{
		Builder: &cpb.Adapter{Params: &aconfig.ListsParams{}},
		Aspect:  &cpb.Aspect{Params: &aconfig.ListsParams{}, Inputs: map[string]string{}},
	}

	lm := newListsManager()
	if _, err := lm.NewCheckExecutor(defaultCfg, newListsBuilder(false), test.Env{}, nil); err != nil {
		t.Errorf("NewCheckExecutor() returned an unexpected error: %v", err)
	}
}

func TestListsManager_NewCheckExecutorErrors(t *testing.T) {
	defaultCfg := &cpb.Combined{
		Builder: &cpb.Adapter{Params: &aconfig.ListsParams{}},
		Aspect:  &cpb.Aspect{Params: &aconfig.ListsParams{}, Inputs: map[string]string{}},
	}

	lm := newListsManager()
	if _, err := lm.NewCheckExecutor(defaultCfg, newListsBuilder(true), test.Env{}, nil); err == nil {
		t.Error("NewCheckExecutor() should have returned an error")
	}
}

type testList struct {
	adapter.Aspect
	closed    bool
	inList    bool
	returnErr bool
}

func (l *testList) Close() error {
	l.closed = true
	return nil
}

func (l *testList) CheckList(symbol string) (bool, error) {
	if l.returnErr {
		return false, errors.New("checklist error")
	}
	return l.inList, nil
}

func TestListsExecutor_Execute(t *testing.T) {
	cases := []struct {
		name   string
		inputs map[string]string
		aspect adapter.ListsAspect
		params *aconfig.ListsParams
	}{
		{"not blacklisted", map[string]string{"ipAddr": "source.ip"}, &testList{}, &aconfig.ListsParams{CheckExpression: "ipAddr", Blacklist: true}},
		{"whitelisted", map[string]string{"ipAddr": "source.ip"}, &testList{inList: true}, &aconfig.ListsParams{CheckExpression: "ipAddr", Blacklist: false}},
	}

	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			e := &listsExecutor{v.inputs, v.aspect, v.params}
			got := e.Execute(test.NewBag(), test.NewIDEval())
			if got.Code != int32(rpc.OK) {
				t.Errorf("Execute() => %v, wanted status with code: %v", got, int32(rpc.OK))
			}
		})
	}
}

func TestListsExecutor_ExecuteErrors(t *testing.T) {

	attrParam := &aconfig.ListsParams{CheckExpression: "ipAddr"}
	blacklistParam := &aconfig.ListsParams{CheckExpression: "ipAddr", Blacklist: true}
	internal := int32(rpc.INTERNAL)
	permDenied := int32(rpc.PERMISSION_DENIED)
	inputMap := map[string]string{"ipAddr": "source.ip"}

	cases := []struct {
		name     string
		inputs   map[string]string
		aspect   adapter.ListsAspect
		params   *aconfig.ListsParams
		wantCode int32
	}{
		{"no inputs", map[string]string{}, &testList{}, attrParam, internal},
		{"checklist error", inputMap, &testList{returnErr: true}, attrParam, internal},
		{"blacklisted", inputMap, &testList{inList: true}, blacklistParam, permDenied},
	}

	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			e := &listsExecutor{v.inputs, v.aspect, v.params}
			got := e.Execute(test.NewBag(), test.NewIDEval())
			if got.Code != v.wantCode {
				t.Errorf("Execute() => %v, wanted status with code: %v", got, v.wantCode)
			}
		})
	}
}

func TestListsExecutor_Close(t *testing.T) {
	inner := &testList{closed: false}
	executor := &listsExecutor{aspect: inner}
	if err := executor.Close(); err != nil {
		t.Errorf("Close() returned an error: %v", err)
	}
	if !inner.closed {
		t.Error("Close() should propagate to wrapped aspect.")
	}
}
