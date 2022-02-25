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

package controller

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	listerv1 "k8s.io/client-go/listers/core/v1"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/keycertbundle"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/inject"
	"istio.io/istio/pkg/test/util/retry"
)

func TestNamespaceController(t *testing.T) {
	client := kube.NewFakeClient()
	watcher := keycertbundle.NewWatcher()
	caBundle := []byte("caBundle")
	watcher.SetAndNotify(nil, nil, caBundle)
	options := Options{
		MeshWatcher: mesh.NewFixedWatcher(&meshconfig.MeshConfig{}),
	}
	nc := NewNamespaceController(client, watcher, options)
	nc.configmapLister = client.KubeInformer().Core().V1().ConfigMaps().Lister()
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
	})
	client.RunAndWait(stop)
	go nc.Run(stop)
	retry.UntilOrFail(t, nc.queue.HasSynced)

	expectedData := map[string]string{
		constants.CACertNamespaceConfigMapDataName: string(caBundle),
	}
	createNamespace(t, client, "foo", nil)
	expectConfigMap(t, nc.configmapLister, CACertNamespaceConfigMap, "foo", expectedData)

	testConfigMapName := "not-root"
	// Make sure random configmap does not get updated
	cmData := createConfigMap(t, client, testConfigMapName, "foo", "k")
	expectConfigMap(t, nc.configmapLister, testConfigMapName, "foo", cmData)

	newCaBundle := []byte("caBundle-new")
	watcher.SetAndNotify(nil, nil, newCaBundle)
	newData := map[string]string{
		constants.CACertNamespaceConfigMapDataName: string(newCaBundle),
	}
	expectConfigMap(t, nc.configmapLister, CACertNamespaceConfigMap, "foo", newData)

	deleteConfigMap(t, client, "foo")
	expectConfigMap(t, nc.configmapLister, CACertNamespaceConfigMap, "foo", newData)

	for _, namespace := range inject.IgnoredNamespaces.UnsortedList() {
		// Create namespace in ignored list, make sure its not created
		createNamespace(t, client, namespace, newData)
		// Configmap in that namespace should not do anything either
		createConfigMap(t, client, testConfigMapName, namespace, "k")
		expectConfigMapNotExist(t, nc.configmapLister, namespace)
	}
}

func TestNamespaceController_WithNamespaceSelectors(t *testing.T) {
	client := kube.NewFakeClient()
	watcher := keycertbundle.NewWatcher()
	caBundle := []byte("caBundle")
	watcher.SetAndNotify(nil, nil, caBundle)
	options := Options{
		MeshWatcher: mesh.NewFixedWatcher(&meshconfig.MeshConfig{
			NamespaceSelectors: []*metav1.LabelSelector{
				{
					MatchLabels: map[string]string{
						"pilot-discovery": "enabled",
					},
				},
				{
					MatchExpressions: []metav1.LabelSelectorRequirement{
						{
							Key:      "env",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"test", "dev"},
						},
					},
				},
			},
		}),
	}
	nc := NewNamespaceController(client, watcher, options)
	nc.configmapLister = client.KubeInformer().Core().V1().ConfigMaps().Lister()
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
	})
	client.RunAndWait(stop)
	go nc.Run(stop)
	retry.UntilOrFail(t, nc.queue.HasSynced)

	expectedData := map[string]string{
		constants.CACertNamespaceConfigMapDataName: string(caBundle),
	}

	nsA := "nsA"
	nsB := "nsB"

	createNamespace(t, client, nsA, map[string]string{"pilot-discovery": "enabled"})
	expectConfigMap(t, nc.configmapLister, CACertNamespaceConfigMap, nsA, expectedData)

	createNamespace(t, client, nsB, map[string]string{})
	expectConfigMapNotExist(t, nc.configmapLister, nsB)

	// test updating namespace with adding select label
	updateNamespace(t, client, nsB, map[string]string{"env": "test"})
	expectConfigMap(t, nc.configmapLister, CACertNamespaceConfigMap, nsB, expectedData)
}

func TestNamespaceController_WithChangingNamespaceSelectors(t *testing.T) {
	client := kube.NewFakeClient()
	watcher := keycertbundle.NewWatcher()
	caBundle := []byte("caBundle")
	watcher.SetAndNotify(nil, nil, caBundle)
	meshWatcher := mesh.NewTestWatcher(&meshconfig.MeshConfig{
		NamespaceSelectors: []*metav1.LabelSelector{
			{
				MatchLabels: map[string]string{
					"app": "foo",
				},
			},
		},
	})
	options := Options{
		MeshWatcher: meshWatcher,
	}
	nc := NewNamespaceController(client, watcher, options)
	nc.configmapLister = client.KubeInformer().Core().V1().ConfigMaps().Lister()
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
	})
	client.RunAndWait(stop)
	go nc.Run(stop)
	retry.UntilOrFail(t, nc.queue.HasSynced)

	expectedData := map[string]string{
		constants.CACertNamespaceConfigMapDataName: string(caBundle),
	}

	nsA := "nsA"
	nsB := "nsB"

	createNamespace(t, client, nsA, map[string]string{"app": "foo"})
	expectConfigMap(t, nc.configmapLister, CACertNamespaceConfigMap, nsA, expectedData)

	createNamespace(t, client, nsB, map[string]string{"app": "bar"})
	expectConfigMapNotExist(t, nc.configmapLister, nsB)

	// update meshConfig
	if err := meshWatcher.Update(&meshconfig.MeshConfig{
		NamespaceSelectors: []*metav1.LabelSelector{
			{
				MatchLabels: map[string]string{
					"app": "bar",
				},
			},
		},
	}, 5); err != nil {
		t.Fatalf("%v", err)
	}
	expectConfigMap(t, nc.configmapLister, CACertNamespaceConfigMap, nsB, expectedData)
}

func deleteConfigMap(t *testing.T, client kubernetes.Interface, ns string) {
	t.Helper()
	_, err := client.CoreV1().ConfigMaps(ns).Get(context.TODO(), CACertNamespaceConfigMap, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CoreV1().ConfigMaps(ns).Delete(context.TODO(), CACertNamespaceConfigMap, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
}

func createConfigMap(t *testing.T, client kubernetes.Interface, name, ns, key string) map[string]string {
	t.Helper()
	data := map[string]string{key: "v"}
	_, err := client.CoreV1().ConfigMaps(ns).Create(context.Background(), &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Data: data,
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func createNamespace(t *testing.T, client kubernetes.Interface, ns string, labels map[string]string) {
	t.Helper()
	if _, err := client.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: labels},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
}

func updateNamespace(t *testing.T, client kubernetes.Interface, ns string, labels map[string]string) {
	t.Helper()
	if _, err := client.CoreV1().Namespaces().Update(context.TODO(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: labels},
	}, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
}

// nolint:unparam
func expectConfigMap(t *testing.T, client listerv1.ConfigMapLister, name, ns string, data map[string]string) {
	t.Helper()
	retry.UntilSuccessOrFail(t, func() error {
		cm, err := client.ConfigMaps(ns).Get(name)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(cm.Data, data) {
			return fmt.Errorf("data mismatch, expected %+v got %+v", data, cm.Data)
		}
		return nil
	}, retry.Timeout(time.Second*10))
}

func expectConfigMapNotExist(t *testing.T, client listerv1.ConfigMapLister, ns string) {
	t.Helper()
	err := retry.Until(func() bool {
		_, err := client.ConfigMaps(ns).Get(CACertNamespaceConfigMap)
		return err == nil
	}, retry.Timeout(time.Millisecond*25))

	if err == nil {
		t.Fatalf("%s namespace should not have istio-ca-root-cert configmap.", ns)
	}
}
