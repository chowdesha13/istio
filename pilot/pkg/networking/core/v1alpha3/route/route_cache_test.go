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

package route

import (
	"reflect"
	"testing"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
)

func TestClearRDSCacheOnDelegateUpdate(t *testing.T) {
	xdsCache := model.NewXdsCache()
	// root virtual service
	root := config.Config{
		Meta: config.Meta{Name: "root", Namespace: "default"},
		Spec: &networking.VirtualService{
			Http: []*networking.HTTPRoute{
				{
					Name: "route",
					Delegate: &networking.Delegate{
						Namespace: "default",
						Name:      "delegate",
					},
				},
			},
		},
	}
	// delegate virtual service
	delegate := model.ConfigKey{Kind: gvk.VirtualService, Name: "delegate", Namespace: "default"}
	// rds cache entry
	entry := Cache{
		VirtualServices:         []config.Config{root},
		DelegateVirtualServices: []model.ConfigKey{delegate},
		ListenerPort:            8080,
	}
	resource := &discovery.Resource{Name: "bar"}

	// add resource to cache
	xdsCache.Add(&entry, &model.PushRequest{Start: time.Now()}, resource)
	if got, found := xdsCache.Get(&entry); !found || !reflect.DeepEqual(got, resource) {
		t.Fatalf("rds cache was not updated")
	}

	// clear cache when delegate virtual service is updated
	// this func is called by `dropCacheForRequest` in `initPushContext`
	xdsCache.Clear(map[model.ConfigKey]struct{}{
		delegate: {},
	})
	if _, found := xdsCache.Get(&entry); found {
		t.Fatalf("rds cache was not cleared")
	}

	// add resource to cache
	xdsCache.Add(&entry, &model.PushRequest{Start: time.Now()}, resource)
	irrelevantDelegate := model.ConfigKey{Kind: gvk.VirtualService, Name: "foo", Namespace: "default"}

	// don't clear cache when irrelevant delegate virtual service is updated
	xdsCache.Clear(map[model.ConfigKey]struct{}{
		irrelevantDelegate: {},
	})
	if got, found := xdsCache.Get(&entry); !found || !reflect.DeepEqual(got, resource) {
		t.Fatalf("rds cache was cleared by irrelevant delegate virtual service update")
	}
}


func TestExtractNamespaceForKubernetesService(t *testing.T) {
	tests := []struct {
		hostname string
		want     string
	}{
		{
			"foo.ns.svc.cluster.local",
			"ns",
		},
		{
			"foo.svc.cluster.local",
			"",
		},
		{
			"svc.ns.svc.svc.svc",
			"ns",
		},
		{
			".svc.",
			"",
		},
		{
			"..svc.",
			"",
		},
		{
			"x.svc.",
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			got, err := extractNamespaceForKubernetesService(tt.hostname)
			if (err != nil) != (tt.want == "") {
				t.Fatalf("unexpected error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("got = %v, want %v", got, tt.want)
			}
		})
	}
}
