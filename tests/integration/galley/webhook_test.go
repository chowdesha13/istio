// Copyright 2019 Istio Authors
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

package galley

import (
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/environment"
	"istio.io/istio/pkg/test/framework/components/environment/kube"
)

// Verify that scaling up/down doesn't modify webhook configuration
func TestWebhookScaling(t *testing.T) {
	framework.NewTest(t).
		// Limit to Kube environment as we're testing integration of webhook with K8s.
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			vwcName := "istio-galley"
			deployName := "istio-galley"
			istioNs := "istio-system"
			sleepDelay := 3 * time.Second // How long to wait to give the reconcile loop an opportunity to act

			env := ctx.Environment().(*kube.Environment)

			startGen := getVwcGeneration(vwcName, t, env)

			// Scale up
			scaleDeployment(istioNs, deployName, 2, t, env)
			// Wait a bit to give the ValidatingWebhookConfiguration reconcile loop an opportunity to act
			time.Sleep(sleepDelay)
			gen := getVwcGeneration(vwcName, t, env)
			if gen != startGen {
				t.Fatalf("ValidatingWebhookConfiguration was updated unexpectedly on scale up")
			}

			// Scale down
			scaleDeployment(istioNs, deployName, 1, t, env)
			// Wait a bit to give the ValidatingWebhookConfiguration reconcile loop an opportunity to act
			time.Sleep(sleepDelay)
			gen = getVwcGeneration(vwcName, t, env)
			if gen != startGen {
				t.Fatalf("ValidatingWebhookConfiguration was updated unexpectedly on scale down")
			}
		})
}

func scaleDeployment(namespace, deployment string, replicas int, t *testing.T, env *kube.Environment) {
	env.ScaleDeployment(namespace, deployment, replicas)
	if err := env.ScaleDeployment(namespace, deployment, replicas); err != nil {
		t.Fatalf("Error scaling deployment %s to %d: %v", deployment, replicas, err)
	}
	if err := env.WaitUntilDeploymentIsReady(namespace, deployment); err != nil {
		t.Fatalf("Error waiting for deployment %s to be ready: %v", deployment, err)
	}
}

func getVwcGeneration(vwcName string, t *testing.T, env *kube.Environment) int64 {
	gen, err := env.GetValidatingWebhookConfigurationGeneration(vwcName)
	if err != nil {
		t.Fatalf("Could not get generation of %s webhook config: %v", vwcName, err)
	}
	return gen
}
