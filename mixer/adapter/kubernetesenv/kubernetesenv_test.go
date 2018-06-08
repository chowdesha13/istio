// Copyright 2017 Istio Authors.
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

package kubernetesenv

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	messagediff "gopkg.in/d4l3k/messagediff.v1"
	appsv1 "k8s.io/api/apps/v1"
	appsv1beta2 "k8s.io/api/apps/v1beta2"
	"k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"istio.io/istio/mixer/adapter/kubernetesenv/config"
	kubernetes_apa_tmpl "istio.io/istio/mixer/adapter/kubernetesenv/template"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/adapter/test"
)

type fakeK8sBuilder struct {
	calledPath string
	calledEnv  adapter.Env
}

func (b *fakeK8sBuilder) build(path string, env adapter.Env) (kubernetes.Interface, error) {
	b.calledPath = path
	b.calledEnv = env
	return fake.NewSimpleClientset(), nil
}

func errorClientBuilder(path string, env adapter.Env) (kubernetes.Interface, error) {
	return nil, errors.New("can't build k8s client")
}

func newFakeBuilder() *builder {
	fb := &fakeK8sBuilder{}
	return newBuilder(fb.build)
}

// note: not using TestAdapterInvariants here because of kubernetes dependency.
// we are aiming for simple unit testing. a larger, more involved integration
// test / e2e test must be written to validate the builder in relation to a
// real kubernetes cluster.
func TestBuilder(t *testing.T) {
	b := newFakeBuilder()

	if err := b.Validate(); err != nil {
		t.Errorf("ValidateConfig() => builder can't validate its default configuration: %v", err)
	}
}

func TestBuilder_BuildAttributesGenerator(t *testing.T) {
	tests := []struct {
		name     string
		clientFn clientFactoryFn
		conf     adapter.Config
		wantErr  bool
	}{
		{"success", (&fakeK8sBuilder{}).build, conf, false},
		{"builder error", errorClientBuilder, conf, true},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			b := newBuilder(v.clientFn)
			b.SetAdapterConfig(v.conf)
			toClose, err := b.Build(context.Background(), test.NewEnv(t))
			if err == nil && v.wantErr {
				t.Fatal("Expected error building adapter")
			}
			if err != nil && !v.wantErr {
				t.Fatalf("Got error, wanted none: %v", err)
			}
			if toClose != nil {
				if err := toClose.Close(); err != nil {
					t.Fatalf("Close() => %v, want success", err)
				}
			}
		})
	}
}

func TestBuilder_ControllerCache(t *testing.T) {
	b := newFakeBuilder()

	for i := 0; i < 10; i++ {
		if _, err := b.Build(context.Background(), test.NewEnv(t)); err != nil {
			t.Errorf("error in builder: %v", err)
		}
	}

	if len(b.controllers) != 1 {
		t.Errorf("Got %v controllers, want 1", len(b.controllers))
	}
}

func TestBuilder_BuildAttributesGeneratorWithEnvVar(t *testing.T) {
	testConf := *conf
	testConf.KubeconfigPath = "please/override"

	tests := []struct {
		name          string
		clientFactory *fakeK8sBuilder
		conf          adapter.Config
		wantOK        bool
	}{
		{"success", &fakeK8sBuilder{}, &testConf, true},
	}

	wantPath := "/want/kubeconfig"
	if err := os.Setenv("KUBECONFIG", wantPath); err != nil {
		t.Fatalf("Could not set KUBECONFIG environment var")
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			b := newBuilder(v.clientFactory.build)
			b.SetAdapterConfig(v.conf)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			{
				_, err := b.Build(ctx, test.NewEnv(t))
				gotOK := err == nil
				if gotOK != v.wantOK {
					t.Fatalf("Got %v, Want %v", err, v.wantOK)
				}
				if v.clientFactory.calledPath != wantPath {
					t.Errorf("Bad kubeconfig path; got %s, want %s", v.clientFactory.calledPath, wantPath)
				}
			}
		})
	}
}

func TestKubegen_Generate(t *testing.T) {

	builder := newBuilder(func(string, adapter.Env) (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(k8sobjs...), nil
	})

	testPodToNoControllerPodIn := &kubernetes_apa_tmpl.Instance{
		SourceUid:      "kubernetes://test-pod.testns",
		DestinationUid: "kubernetes://no-controller-pod.testns",
	}

	testPodToNoControllerPodOut := kubernetes_apa_tmpl.NewOutput()
	testPodToNoControllerPodOut.SetSourceLabels(map[string]string{"app": "test", "something": ""})
	testPodToNoControllerPodOut.SetSourcePodIp(net.ParseIP("10.1.10.1"))
	testPodToNoControllerPodOut.SetSourceHostIp(net.ParseIP("10.1.1.10"))
	testPodToNoControllerPodOut.SetSourceNamespace("testns")
	testPodToNoControllerPodOut.SetSourcePodName("test-pod")
	testPodToNoControllerPodOut.SetSourceServiceAccountName("test")
	testPodToNoControllerPodOut.SetSourceOwner("kubernetes://apis/extensions/v1beta1/namespaces/testns/deployments/test-deployment")
	testPodToNoControllerPodOut.SetSourceWorkloadName("test-deployment")
	testPodToNoControllerPodOut.SetSourceWorkloadNamespace("testns")
	testPodToNoControllerPodOut.SetSourceWorkloadUid("istio://testns/workloads/test-deployment")
	testPodToNoControllerPodOut.SetDestinationPodName("no-controller-pod")
	testPodToNoControllerPodOut.SetDestinationNamespace("testns")
	testPodToNoControllerPodOut.SetDestinationLabels(map[string]string{"app": "some-app"})
	// TODO: Is this correct? For non-controlled pods, should we derive workloads at all?
	testPodToNoControllerPodOut.SetDestinationWorkloadName("no-controller-pod")
	testPodToNoControllerPodOut.SetDestinationWorkloadNamespace("testns")
	testPodToNoControllerPodOut.SetDestinationWorkloadUid("istio://testns/workloads/no-controller-pod")

	altTestPodToAltTestPod2In := &kubernetes_apa_tmpl.Instance{
		SourceUid:      "kubernetes://alt-test-pod.testns",
		DestinationUid: "kubernetes://alt-test-pod-2.testns",
	}

	altTestPodToAltTestPod2Out := kubernetes_apa_tmpl.NewOutput()
	altTestPodToAltTestPod2Out.SetSourceLabels(map[string]string{"app": "some-app"})
	altTestPodToAltTestPod2Out.SetSourceNamespace("testns")
	altTestPodToAltTestPod2Out.SetSourcePodName("alt-test-pod")
	altTestPodToAltTestPod2Out.SetSourceOwner("kubernetes://apis/apps/v1/namespaces/testns/deployments/test-deployment")
	altTestPodToAltTestPod2Out.SetSourceWorkloadName("test-deployment")
	altTestPodToAltTestPod2Out.SetSourceWorkloadNamespace("testns")
	altTestPodToAltTestPod2Out.SetSourceWorkloadUid("istio://testns/workloads/test-deployment")
	altTestPodToAltTestPod2Out.SetDestinationLabels(map[string]string{"app": "some-app"})
	altTestPodToAltTestPod2Out.SetDestinationPodName("alt-test-pod-2")
	altTestPodToAltTestPod2Out.SetDestinationNamespace("testns")
	altTestPodToAltTestPod2Out.SetDestinationOwner("kubernetes://apis/apps/v1beta2/namespaces/testns/deployments/test-deployment")
	altTestPodToAltTestPod2Out.SetDestinationWorkloadName("test-deployment")
	altTestPodToAltTestPod2Out.SetDestinationWorkloadNamespace("testns")
	altTestPodToAltTestPod2Out.SetDestinationWorkloadUid("istio://testns/workloads/test-deployment")

	daemonsetToReplicationControllerIn := &kubernetes_apa_tmpl.Instance{
		SourceUid:      "kubernetes://pod-daemonset.testns",
		DestinationUid: "kubernetes://pod-replicationcontroller.testns",
	}

	daemonsetToReplicaControllerOut := kubernetes_apa_tmpl.NewOutput()
	daemonsetToReplicaControllerOut.SetSourceLabels(map[string]string{"app": "some-app"})
	daemonsetToReplicaControllerOut.SetSourceNamespace("testns")
	daemonsetToReplicaControllerOut.SetSourcePodName("pod-daemonset")
	daemonsetToReplicaControllerOut.SetSourceOwner("kubernetes://apis/apps/v1/namespaces/testns/daemonsets/test-daemonset")
	daemonsetToReplicaControllerOut.SetSourceWorkloadName("test-daemonset")
	daemonsetToReplicaControllerOut.SetSourceWorkloadNamespace("testns")
	daemonsetToReplicaControllerOut.SetSourceWorkloadUid("istio://testns/workloads/test-daemonset")
	daemonsetToReplicaControllerOut.SetDestinationPodName("pod-replicationcontroller")
	daemonsetToReplicaControllerOut.SetDestinationNamespace("testns")
	daemonsetToReplicaControllerOut.SetDestinationOwner("kubernetes://apis/core/v1/namespaces/testns/replicationcontrollers/test-replicationcontroller")
	daemonsetToReplicaControllerOut.SetDestinationLabels(map[string]string{"app": "some-app"})
	daemonsetToReplicaControllerOut.SetDestinationWorkloadName("test-replicationcontroller")
	daemonsetToReplicaControllerOut.SetDestinationWorkloadNamespace("testns")
	daemonsetToReplicaControllerOut.SetDestinationWorkloadUid("istio://testns/workloads/test-replicationcontroller")

	ipDestinationSvcIn := &kubernetes_apa_tmpl.Instance{
		SourceUid:     "kubernetes://pod-job.testns",
		DestinationIp: net.ParseIP("192.168.234.3"),
	}

	ipDestinationOut := kubernetes_apa_tmpl.NewOutput()
	ipDestinationOut.SetSourceNamespace("testns")
	ipDestinationOut.SetSourcePodName("pod-job")
	ipDestinationOut.SetSourceWorkloadName("test-job")
	ipDestinationOut.SetSourceWorkloadNamespace("testns")
	ipDestinationOut.SetSourceWorkloadUid("istio://testns/workloads/test-job")
	ipDestinationOut.SetSourceOwner("kubernetes://apis/core/v1/namespaces/testns/jobs/test-job")
	ipDestinationOut.SetDestinationLabels(map[string]string{"app": "ipAddr"})
	ipDestinationOut.SetDestinationNamespace("testns")
	ipDestinationOut.SetDestinationPodName("ip-svc-pod")
	ipDestinationOut.SetDestinationPodIp(net.ParseIP("192.168.234.3"))
	ipDestinationOut.SetDestinationOwner("kubernetes://apis/apps/v1/namespaces/testns/deployments/test-deployment")
	ipDestinationOut.SetDestinationWorkloadName("test-deployment")
	ipDestinationOut.SetDestinationWorkloadNamespace("testns")
	ipDestinationOut.SetDestinationWorkloadUid("istio://testns/workloads/test-deployment")

	notFoundToNoControllerIn := &kubernetes_apa_tmpl.Instance{
		SourceUid:      "kubernetes://not-found-pod.testns",
		DestinationUid: "kubernetes://test-pod.testns",
	}

	notFoundToNoControllerOut := kubernetes_apa_tmpl.NewOutput()
	notFoundToNoControllerOut.SetDestinationLabels(map[string]string{"app": "test", "something": ""})
	notFoundToNoControllerOut.SetDestinationPodIp(net.ParseIP("10.1.10.1"))
	notFoundToNoControllerOut.SetDestinationHostIp(net.ParseIP("10.1.1.10"))
	notFoundToNoControllerOut.SetDestinationNamespace("testns")
	notFoundToNoControllerOut.SetDestinationPodName("test-pod")
	notFoundToNoControllerOut.SetDestinationServiceAccountName("test")
	notFoundToNoControllerOut.SetDestinationOwner("kubernetes://apis/extensions/v1beta1/namespaces/testns/deployments/test-deployment")
	notFoundToNoControllerOut.SetDestinationWorkloadName("test-deployment")
	notFoundToNoControllerOut.SetDestinationWorkloadNamespace("testns")
	notFoundToNoControllerOut.SetDestinationWorkloadUid("istio://testns/workloads/test-deployment")

	notKubernetesIn := &kubernetes_apa_tmpl.Instance{
		SourceUid: "something-else://other-scheme",
	}

	ipToReplicaSetSvcIn := &kubernetes_apa_tmpl.Instance{
		DestinationUid: "kubernetes://replicaset-with-no-deployment-pod.testns",
		SourceIp:       net.ParseIP("192.168.234.3"),
	}
	ipToReplicaSetSvcOut := kubernetes_apa_tmpl.NewOutput()
	ipToReplicaSetSvcOut.SetSourceLabels(map[string]string{"app": "ipAddr"})
	ipToReplicaSetSvcOut.SetSourceNamespace("testns")
	ipToReplicaSetSvcOut.SetSourcePodName("ip-svc-pod")
	ipToReplicaSetSvcOut.SetSourcePodIp(net.ParseIP("192.168.234.3"))
	ipToReplicaSetSvcOut.SetSourceOwner("kubernetes://apis/apps/v1/namespaces/testns/deployments/test-deployment")
	ipToReplicaSetSvcOut.SetSourceWorkloadName("test-deployment")
	ipToReplicaSetSvcOut.SetSourceWorkloadNamespace("testns")
	ipToReplicaSetSvcOut.SetSourceWorkloadUid("istio://testns/workloads/test-deployment")
	ipToReplicaSetSvcOut.SetDestinationLabels(map[string]string{"app": "some-app"})
	ipToReplicaSetSvcOut.SetDestinationNamespace("testns")
	ipToReplicaSetSvcOut.SetDestinationOwner("kubernetes://apis/apps/v1/namespaces/testns/replicasets/not-found-replicaset")
	ipToReplicaSetSvcOut.SetDestinationPodName("replicaset-with-no-deployment-pod")
	ipToReplicaSetSvcOut.SetDestinationWorkloadName("not-found-replicaset")
	ipToReplicaSetSvcOut.SetDestinationWorkloadNamespace("testns")
	ipToReplicaSetSvcOut.SetDestinationWorkloadUid("istio://testns/workloads/not-found-replicaset")

	replicasetToReplicaSetIn := &kubernetes_apa_tmpl.Instance{
		DestinationUid: "kubernetes://extv1beta1-replicaset-with-no-deployment-pod.testns",
		SourceUid:      "kubernetes://appsv1beta2-replicaset-with-no-deployment-pod.testns",
	}

	replicaSetToReplicaSetOut := kubernetes_apa_tmpl.NewOutput()
	replicaSetToReplicaSetOut.SetSourceLabels(map[string]string{"app": "some-app"})
	replicaSetToReplicaSetOut.SetSourceNamespace("testns")
	replicaSetToReplicaSetOut.SetSourceOwner("kubernetes://apis/apps/v1beta2/namespaces/testns/replicasets/not-found-replicaset")
	replicaSetToReplicaSetOut.SetSourcePodName("appsv1beta2-replicaset-with-no-deployment-pod")
	replicaSetToReplicaSetOut.SetSourceWorkloadName("not-found-replicaset")
	replicaSetToReplicaSetOut.SetSourceWorkloadNamespace("testns")
	replicaSetToReplicaSetOut.SetSourceWorkloadUid("istio://testns/workloads/not-found-replicaset")
	replicaSetToReplicaSetOut.SetDestinationLabels(map[string]string{"app": "some-app"})
	replicaSetToReplicaSetOut.SetDestinationNamespace("testns")
	replicaSetToReplicaSetOut.SetDestinationOwner("kubernetes://apis/extensions/v1beta1/namespaces/testns/replicasets/test-replicaset-without-deployment")
	replicaSetToReplicaSetOut.SetDestinationPodName("extv1beta1-replicaset-with-no-deployment-pod")
	replicaSetToReplicaSetOut.SetDestinationWorkloadName("test-replicaset-without-deployment")
	replicaSetToReplicaSetOut.SetDestinationWorkloadNamespace("testns")
	replicaSetToReplicaSetOut.SetDestinationWorkloadUid("istio://testns/workloads/test-replicaset-without-deployment")

	tests := []struct {
		name   string
		inputs *kubernetes_apa_tmpl.Instance
		want   *kubernetes_apa_tmpl.Output
		params *config.Params
	}{
		{"test-pod to no-controller-pod", testPodToNoControllerPodIn, testPodToNoControllerPodOut, conf},
		{"alt-test-pod to alt-test-pod-2", altTestPodToAltTestPod2In, altTestPodToAltTestPod2Out, conf},
		{"pod-daemonset to pod-replicacontroller", daemonsetToReplicationControllerIn, daemonsetToReplicaControllerOut, conf},
		{"not-found-pod to test-pod", notFoundToNoControllerIn, notFoundToNoControllerOut, conf},
		{"pod-job to ip-svc-pod", ipDestinationSvcIn, ipDestinationOut, conf},
		{"ip-svc-pod to replicaset", ipToReplicaSetSvcIn, ipToReplicaSetSvcOut, conf},
		{"replicasets with no deployments", replicasetToReplicaSetIn, replicaSetToReplicaSetOut, conf},
		{"not-k8s", notKubernetesIn, kubernetes_apa_tmpl.NewOutput(), conf},
	}

	for _, v := range tests {
		t.Run(v.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			builder.SetAdapterConfig(v.params)

			kg, err := builder.Build(ctx, test.NewEnv(t))
			if err != nil {
				t.Fatal(err)
			}
			got, err := kg.(*handler).GenerateKubernetesAttributes(ctx, v.inputs)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if diff, equal := messagediff.PrettyDiff(v.want, got); !equal {
				t.Errorf("Generate() => %#v\n%s", got, diff)
			}
		})
	}
}

// Kubernetes Runtime Object for Tests

var trueVar = true
var falseVar = false

var k8sobjs = []runtime.Object{
	// replicasets
	&extv1beta1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-replicaset-with-deployment",
			Namespace: "testns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "extensions/v1beta1",
					Controller: &trueVar,
					Kind:       "Deployment",
					Name:       "test-deployment",
				},
				{
					APIVersion: "extensions/v1beta1",
					Controller: &falseVar,
					Kind:       "Deployment",
					Name:       "not-exist-deployment",
				},
			},
		},
	},
	&extv1beta1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-replicaset-without-deployment",
			Namespace: "testns",
		},
	},
	&appsv1beta2.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-appsv1beta2-replicaset-with-deployment",
			Namespace: "testns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1beta2",
					Controller: &trueVar,
					Kind:       "Deployment",
					Name:       "test-deployment",
				},
			},
		},
	},
	&appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-appsv1-replicaset-with-deployment",
			Namespace: "testns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Controller: &trueVar,
					Kind:       "Deployment",
					Name:       "test-deployment",
				},
			},
		},
	},
	// pods
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "testns",
			Labels: map[string]string{
				"app":       "test",
				"something": "",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "extensions/v1beta1",
					Controller: &trueVar,
					Kind:       "ReplicaSet",
					Name:       "test-replicaset-with-deployment",
				},
			},
		},
		Status: v1.PodStatus{
			HostIP: "10.1.1.10",
			PodIP:  "10.1.10.1",
		},
		Spec: v1.PodSpec{
			ServiceAccountName: "test",
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alt-test-pod",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Controller: &trueVar,
					Kind:       "ReplicaSet",
					Name:       "test-appsv1-replicaset-with-deployment",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alt-test-pod-2",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1beta2",
					Controller: &trueVar,
					Kind:       "ReplicaSet",
					Name:       "test-appsv1beta2-replicaset-with-deployment",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "extv1beta1-replicaset-with-no-deployment-pod",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "extensions/v1beta1",
					Controller: &trueVar,
					Kind:       "ReplicaSet",
					Name:       "test-replicaset-without-deployment",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "appsv1beta2-replicaset-with-no-deployment-pod",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1beta2",
					Controller: &trueVar,
					Kind:       "ReplicaSet",
					Name:       "not-found-replicaset",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "replicaset-with-no-deployment-pod",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Controller: &trueVar,
					Kind:       "ReplicaSet",
					Name:       "not-found-replicaset",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-controller-pod",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-daemonset",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Controller: &trueVar,
					Kind:       "DaemonSet",
					Name:       "test-daemonset",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-replicationcontroller",
			Namespace: "testns",
			Labels:    map[string]string{"app": "some-app"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "core/v1",
					Controller: &trueVar,
					Kind:       "ReplicationController",
					Name:       "test-replicationcontroller",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-job",
			Namespace: "testns",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "core/v1",
					Controller: &trueVar,
					Kind:       "Job",
					Name:       "test-job",
				},
			},
		},
	},
	&v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ip-svc-pod",
			Namespace: "testns",
			Labels:    map[string]string{"app": "ipAddr"},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: "apps/v1",
					Controller: &trueVar,
					Kind:       "ReplicaSet",
					Name:       "test-appsv1-replicaset-with-deployment",
				},
			},
		},
		Status: v1.PodStatus{PodIP: "192.168.234.3"},
	},
}
