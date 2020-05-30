//  Copyright Istio Authors
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

package sdsingressk8sca

import (
	"testing"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/resource/environment"
	"istio.io/istio/tests/integration/security/sds_ingress/util"
)

var (
	inst istio.Instance
)

func TestMain(m *testing.M) {
	// Integration test for the ingress SDS multiple Gateway flow when
	// the control plane certificate provider is k8s CA.
	framework.
		NewSuite("sds_ingress_k8sca", m).
		RequireSingleCluster().
		SetupOnEnv(environment.Kube, istio.Setup(&inst, setupConfig)).
		Run()

}

func setupConfig(cfg *istio.Config) {
	if cfg == nil {
		return
	}

	cfg.ControlPlaneValues = `
values:
  global:
    pilotCertProvider: kubernetes
`
}

func TestMtlsGatewaysK8sca(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			util.RunTestMultiMtlsGateways(ctx, inst)
		})
}

func TestTlsGatewaysK8sca(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			util.RunTestMultiTLSGateways(ctx, inst)
		})
}
