// Copyright 2020 Istio Authors
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

package util

import (
	"fmt"
	"testing"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

const (
	configMapName = "test-configmap-name"
	namespaceName = "test-ns"
	dataName      = "test-data-name"
)

func TestUpdateDataInConfigMap(t *testing.T) {
	gvr := schema.GroupVersionResource{
		Resource: "configmaps",
		Version:  "v1",
	}
	testMeta := metav1.ObjectMeta{Namespace: namespaceName, Name: configMapName}
	testData := map[string]string{
		"test-key": "test-data",
	}
	testCases := []struct {
		name              string
		existingConfigMap *v1.ConfigMap
		expectedActions   []ktesting.Action
		expectedErr       string
	}{
		{
			name:        "non-existing ConfigMap",
			expectedErr: "cannot update nil configmap",
		},
		{
			name:              "existing empty ConfigMap",
			existingConfigMap: createConfigMap(namespaceName, configMapName, map[string]string{}),
			expectedActions: []ktesting.Action{
				ktesting.NewUpdateAction(gvr, namespaceName, createConfigMap(namespaceName, configMapName, testData)),
			},
			expectedErr: "",
		},
		{
			name:              "existing nop ConfigMap",
			existingConfigMap: createConfigMap(namespaceName, configMapName, testData),
			expectedActions:   []ktesting.Action{},
			expectedErr:       "",
		},
		{
			name:              "existing with other keys",
			existingConfigMap: createConfigMap(namespaceName, configMapName, map[string]string{"foo": "bar"}),
			expectedActions: []ktesting.Action{
				ktesting.NewUpdateAction(gvr, namespaceName, createConfigMap(namespaceName, configMapName,
					map[string]string{"test-key": "test-data", "foo": "bar"})),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewSimpleClientset()
			if tc.existingConfigMap != nil {
				if _, err := client.CoreV1().ConfigMaps(testMeta.Namespace).Create(tc.existingConfigMap); err != nil {
					t.Errorf("failed to create configmap %v", err)
				}
			}
			client.ClearActions()
			err := UpdateDataInConfigMap(client.CoreV1(), tc.existingConfigMap, testData)
			if err != nil && err.Error() != tc.expectedErr {
				t.Errorf("actual error (%s) different from expected error (%s).", err.Error(), tc.expectedErr)
			}
			if err == nil {
				if tc.expectedErr != "" {
					t.Errorf("expecting error %s but got no error", tc.expectedErr)
				} else if err := checkActions(client.Actions(), tc.expectedActions); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestInsertDataToConfigMap(t *testing.T) {
	gvr := schema.GroupVersionResource{
		Resource: "configmaps",
		Version:  "v1",
	}
	testData := map[string]string{
		"test-key": "test-data",
	}
	testCases := []struct {
		name              string
		meta              metav1.ObjectMeta
		existingConfigMap *v1.ConfigMap
		data              map[string]string
		expectedActions   []ktesting.Action
		expectedErr       string
		client            *fake.Clientset
	}{
		{
			name:              "non-existing ConfigMap",
			existingConfigMap: nil,
			data:              testData,
			meta:              metav1.ObjectMeta{Namespace: namespaceName, Name: configMapName},
			expectedActions: []ktesting.Action{
				ktesting.NewGetAction(gvr, namespaceName, configMapName),
				ktesting.NewCreateAction(gvr, namespaceName, createConfigMap(namespaceName,
					configMapName, testData)),
			},
			expectedErr: "",
		},
		{
			name:              "existing ConfigMap",
			meta:              metav1.ObjectMeta{Namespace: namespaceName, Name: configMapName},
			existingConfigMap: createConfigMap(namespaceName, configMapName, map[string]string{}),
			data:              testData,
			expectedActions: []ktesting.Action{
				ktesting.NewGetAction(gvr, namespaceName, configMapName),
				ktesting.NewUpdateAction(gvr, namespaceName, createConfigMap(namespaceName, configMapName, testData)),
			},
			expectedErr: "",
		},
		{
			name:              "creation failure for ConfigMap",
			existingConfigMap: nil,
			data:              testData,
			meta:              metav1.ObjectMeta{Namespace: namespaceName, Name: configMapName},
			expectedActions: []ktesting.Action{
				ktesting.NewGetAction(gvr, namespaceName, configMapName),
				ktesting.NewGetAction(gvr, namespaceName, configMapName),
				ktesting.NewCreateAction(gvr, namespaceName, createConfigMap(namespaceName, configMapName,
					map[string]string{dataName: "test-data"})),
			},
			expectedErr: fmt.Sprintf("error when creating configmap %v: no permission to create configmap",
				configMapName),
			client: createConfigMapDisabledClient(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var client *fake.Clientset
			if tc.client == nil {
				client = fake.NewSimpleClientset()
			} else {
				client = tc.client
			}
			if tc.existingConfigMap != nil {
				if _, err := client.CoreV1().ConfigMaps(tc.meta.Namespace).Create(tc.existingConfigMap); err != nil {
					t.Errorf("failed to create configmap %v", err)
				}
			}
			client.ClearActions()
			err := InsertDataToConfigMap(client.CoreV1(), tc.meta, tc.data)
			if err != nil && err.Error() != tc.expectedErr {
				t.Errorf("actual error (%s) different from expected error (%s).", err.Error(), tc.expectedErr)
			}
			if err == nil {
				if tc.expectedErr != "" {
					t.Errorf("expecting error %s but got no error", tc.expectedErr)
				} else if err := checkActions(client.Actions(), tc.expectedActions); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func createConfigMapDisabledClient() *fake.Clientset {
	client := &fake.Clientset{}
	client.AddReactor("get", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, &v1.ConfigMap{}, errors.NewNotFound(v1.Resource("configmaps"), configMapName)
	})
	client.AddReactor("create", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, &v1.ConfigMap{}, errors.NewUnauthorized("no permission to create configmap")
	})
	return client
}

// nolint: unparam
func createConfigMap(namespace, configName string, data map[string]string) *v1.ConfigMap {
	return &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configName,
			Namespace: namespace,
		},
		Data: data,
	}
}

func checkActions(actual, expected []ktesting.Action) error {
	if len(actual) != len(expected) {
		return fmt.Errorf("unexpected number of actions, want %d but got %d", len(expected), len(actual))
	}

	for i, action := range actual {
		expectedAction := expected[i]
		verb := expectedAction.GetVerb()
		resource := expectedAction.GetResource().Resource
		if !action.Matches(verb, resource) {
			return fmt.Errorf("unexpected %dth action, want \n%+v but got \n%+v", i, expectedAction, action)
		}
	}

	return nil
}
