/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
)

func TestServiceSelectorCache_GetPodServiceMemberships(t *testing.T) {
	fakeInformerFactory := informers.NewSharedInformerFactory(&fake.Clientset{}, 0*time.Second)
	for i := 0; i < 3; i++ {
		service := &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("service-%d", i),
				Namespace: "test",
			},
			Spec: v1.ServiceSpec{
				Selector: map[string]string{
					"app": fmt.Sprintf("test-%d", i),
				},
			},
		}
		fakeInformerFactory.Core().V1().Services().Informer().GetStore().Add(service)
	}
	var pods []*v1.Pod
	for i := 0; i < 5; i++ {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "test",
				Name:      fmt.Sprintf("test-pod-%d", i),
				Labels: map[string]string{
					"app":   fmt.Sprintf("test-%d", i),
					"label": fmt.Sprintf("label-%d", i),
				},
			},
		}
		pods = append(pods, pod)
	}

	scache := NewServiceSelectorCache()
	tests := []struct {
		name   string
		pod    *v1.Pod
		expect sets.String
	}{
		{
			name:   "get servicesMemberships for pod-0",
			pod:    pods[0],
			expect: sets.NewString("test/service-0"),
		},
		{
			name:   "get servicesMemberships for pod-1",
			pod:    pods[1],
			expect: sets.NewString("test/service-1"),
		},
		{
			name:   "get servicesMemberships for pod-2",
			pod:    pods[2],
			expect: sets.NewString("test/service-2"),
		},
		{
			name:   "get servicesMemberships for pod-3",
			pod:    pods[3],
			expect: sets.NewString(),
		},
		{
			name:   "get servicesMemberships for pod-4",
			pod:    pods[4],
			expect: sets.NewString(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			services, err := scache.GetPodServiceMemberships(fakeInformerFactory.Core().V1().Services().Lister(), test.pod)
			if err != nil {
				t.Errorf("Error from cache.GetPodServiceMemberships: %v", err)
			} else {
				set := sets.String{}
				for _, s := range services {
					key, _ := cache.DeletionHandlingMetaNamespaceKeyFunc(s)
					set.Insert(key)
				}
				if !set.Equal(test.expect) {
					t.Errorf("Expect service %v, but got %v", test.expect, set)
				}
			}
		})
	}
}

func TestServiceSelectorCache_Update(t *testing.T) {
	var selectors []labels.Selector
	for i := 0; i < 5; i++ {
		selector := labels.Set(map[string]string{"app": fmt.Sprintf("test-%d", i)}).AsSelectorPreValidated()
		selectors = append(selectors, selector)
	}
	tests := []struct {
		name   string
		key    string
		cache  *ServiceSelectorCache
		update map[string]string
		expect labels.Selector
	}{
		{
			name:   "add test/service-0",
			key:    "test/service-0",
			cache:  generateServiceSelectorCache(map[string]labels.Selector{}),
			update: map[string]string{"app": "test-0"},
			expect: selectors[0],
		},
		{
			name:   "add test/service-1",
			key:    "test/service-1",
			cache:  generateServiceSelectorCache(map[string]labels.Selector{"test/service-0": selectors[0]}),
			update: map[string]string{"app": "test-1"},
			expect: selectors[1],
		},
		{
			name:   "update test/service-2",
			key:    "test/service-2",
			cache:  generateServiceSelectorCache(map[string]labels.Selector{"test/service-2": selectors[2]}),
			update: map[string]string{"app": "test-0"},
			expect: selectors[0],
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selector := test.cache.Update(test.key, test.update)
			if !reflect.DeepEqual(selector, test.expect) {
				t.Errorf("Expect selector %v , but got %v", test.expect, selector)
			}
		})
	}
}

func generateServiceSelectorCache(cache map[string]labels.Selector) *ServiceSelectorCache {
	return &ServiceSelectorCache{
		cache: cache,
	}
}

func BenchmarkGetPodServiceMemberships(b *testing.B) {
	// init fake service informer.
	fakeInformerFactory := informers.NewSharedInformerFactory(&fake.Clientset{}, 0*time.Second)
	for i := 0; i < 1000; i++ {
		service := &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("service-%d", i),
				Namespace: "test",
			},
			Spec: v1.ServiceSpec{
				Selector: map[string]string{
					"app": fmt.Sprintf("test-%d", i),
				},
			},
		}
		fakeInformerFactory.Core().V1().Services().Informer().GetStore().Add(service)
	}

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "test",
			Name:      "test-pod-0",
			Labels: map[string]string{
				"app": "test-0",
			},
		},
	}

	cache := NewServiceSelectorCache()
	expect := sets.NewString("test/service-0")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		services, err := cache.GetPodServiceMemberships(fakeInformerFactory.Core().V1().Services().Lister(), pod)
		if err != nil {
			b.Fatalf("Error from GetPodServiceMemberships(): %v", err)
		}
		if len(services) != len(expect) {
			b.Errorf("Expect services size %d, but got: %v", len(expect), len(services))
		}
	}
}
