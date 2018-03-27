//  Copyright 2018 Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package resource

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"istio.io/istio/galley/pkg/testing/machinery/mock"
)

func TestDeleteAll_NewClientError(t *testing.T) {
	i := mock.NewInterface()
	i.DynamicFn = func(gv schema.GroupVersion, kind string, listKind string) (dynamic.Interface, error) {
		return nil, fmt.Errorf("newDynamicClient error")
	}

	err := DeleteAll(i, "foos", "foo", "fooList", schema.GroupVersion{}, []string{"ns1"})
	if err == nil || err.Error() != "newDynamicClient error" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeleteAll_Basic(t *testing.T) {
	i := mock.NewInterface()

	err := DeleteAll(i, "foos", "foo", "fooList", schema.GroupVersion{}, []string{"ns1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := `
DeleteCollection
`
	check(t, i.MockDynamic.String(), expected)
}

func TestDeleteAll_Error(t *testing.T) {
	i := mock.NewInterface()

	i.MockDynamic.MockResource.ErrorResult = errors.New("some DeleteCollection error")

	err := DeleteAll(i, "foos", "foo", "fooList", schema.GroupVersion{}, []string{"ns1"})
	if err == nil || err.Error() != "some DeleteCollection error" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGetNamespaces(t *testing.T) {
	i := mock.NewInterface()

	i.MockKubernetes.MockCoreV1.MockNamespaces.ListResult = &v1.NamespaceList{
		Items: []v1.Namespace{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "foo"},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "bar"},
			},
		},
	}

	ns, err := GetNamespaces(i)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ns) != 2 {
		t.Fatalf("unexpected ns len: %d", len(ns))
	}
}

func TestGetNamespaces_Empty(t *testing.T) {
	i := mock.NewInterface()

	i.MockKubernetes.MockCoreV1.MockNamespaces.ListResult = &v1.NamespaceList{}

	ns, err := GetNamespaces(i)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(ns) != 0 {
		t.Fatalf("unexpected ns len: %d", len(ns))
	}
}

func TestGetNamespaces_ListError(t *testing.T) {
	i := mock.NewInterface()

	i.MockKubernetes.MockCoreV1.MockNamespaces.ErrorResult = errors.New("some list error")

	_, err := GetNamespaces(i)
	if err == nil || err.Error() != "some list error" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func check(t *testing.T, actual string, expected string) {
	if strings.TrimSpace(actual) != strings.TrimSpace(expected) {
		t.Fatalf("mismatch.\nGot:\n%s\nWanted:\n%s\n", actual, expected)
	}
}
