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

package kubeclient // import "istio.io/istio/tools/bug-report/pkg/kubeclient"

import (
	"k8s.io/client-go/kubernetes"
	//  Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"istio.io/istio/pkg/kube"
)

const (
	defaultTimeoutDurationStr = "10m"
)

// New creates a rest.Config and Clientset from the given kubeconfig path and Context.
func New(kubeconfig, kubeContext string, qpsLimit int) (*rest.Config, *kubernetes.Clientset, error) {
	clientConfig := kube.BuildClientCmd(kubeconfig, kubeContext, func(co *clientcmd.ConfigOverrides) {
		co.Timeout = defaultTimeoutDurationStr
	})
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, nil, err
	}
	if qpsLimit > 0 {
		restConfig.QPS = float32(qpsLimit)
		restConfig.Burst = qpsLimit * 2
	}

	clientset, err := kubernetes.NewForConfig(kube.SetRestDefaults(restConfig))
	if err != nil {
		return nil, nil, err
	}

	return restConfig, clientset, nil
}
