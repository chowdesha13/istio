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
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	meshconfig "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pilot/pkg/keycertbundle"
	"istio.io/istio/pilot/pkg/server"
	"istio.io/istio/pilot/pkg/serviceregistry/aggregate"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/remoteclusters"
	"istio.io/istio/pkg/test/util/retry"
)

const (
	testSecretNameSpace = "istio-system"
	DomainSuffix        = "fake_domain"
	ResyncPeriod        = 1 * time.Second
)

var mockserviceController = aggregate.NewController(aggregate.Options{})

func createMultiClusterSecret(k8s kube.Client, sname, cname string) error {
	data := map[string][]byte{}
	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sname,
			Namespace: testSecretNameSpace,
			Labels: map[string]string{
				remoteclusters.MultiClusterSecretLabel: "true",
			},
		},
		Data: map[string][]byte{},
	}

	data[cname] = []byte("Test")
	secret.Data = data
	_, err := k8s.CoreV1().Secrets(testSecretNameSpace).Create(context.TODO(), &secret, metav1.CreateOptions{})
	return err
}

func deleteMultiClusterSecret(k8s kube.Client, sname string) error {
	var immediate int64

	return k8s.CoreV1().Secrets(testSecretNameSpace).Delete(
		context.TODO(),
		sname, metav1.DeleteOptions{GracePeriodSeconds: &immediate})
}

func verifyControllers(t *testing.T, m *Multicluster, expectedControllerCount int, timeoutName string) {
	t.Helper()
	retry.UntilOrFail(t, func() bool {
		m.m.Lock()
		defer m.m.Unlock()
		return len(m.remoteKubeControllers) == expectedControllerCount
	}, retry.Message(timeoutName), retry.Delay(time.Millisecond*10), retry.Timeout(time.Second*5))
}

func initController(client kube.ExtendedClient, ns string, stop <-chan struct{}, mc *Multicluster) {
	sc := remoteclusters.NewController(client, ns, "")
	sc.AddHandler(mc)
	go sc.Run(stop)
	cache.WaitForCacheSync(stop, sc.HasSynced)
}

func Test_KubeSecretController(t *testing.T) {
	remoteclusters.BuildClientsFromConfig = func(kubeConfig []byte) (kube.Client, error) {
		return kube.NewFakeClient(), nil
	}
	clientset := kube.NewFakeClient()
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
	})
	s := server.New()
	mc := NewMulticluster(
		"pilot-abc-123",
		clientset,
		testSecretNameSpace,
		Options{
			DomainSuffix:          DomainSuffix,
			ResyncPeriod:          ResyncPeriod,
			SyncInterval:          time.Microsecond,
			MeshWatcher:           mesh.NewFixedWatcher(&meshconfig.MeshConfig{}),
			MeshServiceController: mockserviceController,
		}, nil, nil, "default", false, nil, s)
	initController(clientset, testSecretNameSpace, stop, mc)
	clientset.RunAndWait(stop)
	_ = s.Start(stop)
	go func() {
		_ = mc.Run(stop)
	}()

	// Create the multicluster secret. Sleep to allow created remote
	// controller to start and callback add function to be called.
	err := createMultiClusterSecret(clientset, "test-secret-1", "test-remote-cluster-1")
	if err != nil {
		t.Fatalf("Unexpected error on secret create: %v", err)
	}

	// Test - Verify that the remote controller has been added.
	verifyControllers(t, mc, 1, "create remote controller")

	// Delete the mulicluster secret.
	err = deleteMultiClusterSecret(clientset, "test-secret-1")
	if err != nil {
		t.Fatalf("Unexpected error on secret delete: %v", err)
	}

	// Test - Verify that the remote controller has been removed.
	verifyControllers(t, mc, 0, "delete remote controller")
}

func Test_KubeSecretController_ExternalIstiod_MultipleClusters(t *testing.T) {
	externalIstiod := features.ExternalIstiod
	webhookName := features.InjectionWebhookConfigName
	features.ExternalIstiod = true
	features.InjectionWebhookConfigName = ""
	defer func() {
		features.ExternalIstiod = externalIstiod
		features.InjectionWebhookConfigName = webhookName
	}()
	clientset := kube.NewFakeClient()
	remoteclusters.BuildClientsFromConfig = func(kubeConfig []byte) (kube.Client, error) {
		return kube.NewFakeClient(), nil
	}
	stop := make(chan struct{})
	t.Cleanup(func() {
		close(stop)
	})
	s := server.New()
	certWatcher := keycertbundle.NewWatcher()
	mc := NewMulticluster(
		"pilot-abc-123",
		clientset,
		testSecretNameSpace,
		Options{
			DomainSuffix:          DomainSuffix,
			ResyncPeriod:          ResyncPeriod,
			SyncInterval:          time.Microsecond,
			MeshWatcher:           mesh.NewFixedWatcher(&meshconfig.MeshConfig{}),
			MeshServiceController: mockserviceController,
		}, nil, certWatcher, "default", false, nil, s)
	initController(clientset, testSecretNameSpace, stop, mc)
	clientset.RunAndWait(stop)
	_ = s.Start(stop)
	go func() {
		_ = mc.Run(stop)
	}()

	// Create the multicluster secret. Sleep to allow created remote
	// controller to start and callback add function to be called.
	err := createMultiClusterSecret(clientset, "test-secret-1", "test-remote-cluster-1")
	if err != nil {
		t.Fatalf("Unexpected error on secret create: %v", err)
	}

	// Test - Verify that the remote controller has been added.
	verifyControllers(t, mc, 1, "create remote controller")

	// Create second multicluster secret. Sleep to allow created remote
	// controller to start and callback add function to be called.
	err = createMultiClusterSecret(clientset, "test-secret-2", "test-remote-cluster-2")
	if err != nil {
		t.Fatalf("Unexpected error on secret create: %v", err)
	}

	// Test - Verify that the remote controller has been added.
	verifyControllers(t, mc, 2, "create remote controller")

	// Delete the first mulicluster secret.
	err = deleteMultiClusterSecret(clientset, "test-secret-1")
	if err != nil {
		t.Fatalf("Unexpected error on secret delete: %v", err)
	}

	// Test - Verify that the remote controller has been removed.
	verifyControllers(t, mc, 1, "delete remote controller")

	// Delete the second mulicluster secret.
	err = deleteMultiClusterSecret(clientset, "test-secret-2")
	if err != nil {
		t.Fatalf("Unexpected error on secret delete: %v", err)
	}

	// Test - Verify that the remote controller has been removed.
	verifyControllers(t, mc, 0, "delete remote controller")
}
