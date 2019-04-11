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

// Verify reachability under different authN scenario.
package reachability

import (
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/apps"
	"istio.io/istio/pkg/test/framework/components/environment"
	"istio.io/istio/pkg/test/framework/components/environment/kube"
	"istio.io/istio/pkg/test/framework/components/istio"
	pilot2 "istio.io/istio/pkg/test/framework/components/pilot"
	connect "istio.io/istio/pkg/test/util/connection"
	"istio.io/istio/pkg/test/util/policy"
	"istio.io/istio/pkg/test/util/retry"
)

func TestMutualTlsReachability(t *testing.T) {
	ctx := framework.NewContext(t)
	defer ctx.Done(t)
	ctx.RequireOrSkip(t, environment.Kube)

	istioCfg, err := istio.DefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Get istio config: %v", err)
	}

	env := ctx.Environment().(*kube.Environment)

	pilot := pilot2.NewOrFail(t, ctx, pilot2.Config{})
	appsInstance := apps.NewOrFail(ctx, t, apps.Config{Pilot: pilot})

	aApp, _ := appsInstance.GetAppOrFail("a", t).(apps.KubeApp)
	bApp, _ := appsInstance.GetAppOrFail("b", t).(apps.KubeApp)

	headlessApp, _ := appsInstance.GetAppOrFail("headless", t).(apps.KubeApp)
	// App without sidecar.
	nakedApp, _ := appsInstance.GetAppOrFail("t", t).(apps.KubeApp)

	testCases := []struct {
		configFile  string
		namespace   string
		connections []connect.Connection
	}{
		{
			configFile: "global-mtls-on.yaml",
			connections: []connect.Connection{
				{
					From:            aApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
				{
					From:            aApp,
					To:              headlessApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
				{
					From:            nakedApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: false,
				},
			},
		},
		{
			configFile: "global-mtls-permissive.yaml",
			connections: []connect.Connection{
				{
					From:            aApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
				{
					From:            nakedApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
			},
		},
		{
			configFile: "global-mtls-off.yaml",
			connections: []connect.Connection{
				{
					From:            aApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
				{
					From:            nakedApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
			},
		},
		{
			configFile: "single-port-mtls-on.yaml",
			namespace:  appsInstance.Namespace().Name(),
			connections: []connect.Connection{
				{
					From:            aApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: false,
				},
				{
					From:            nakedApp,
					To:              bApp,
					Port:            80,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: false,
				},
				{
					From:            aApp,
					To:              bApp,
					Port:            90,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
				{
					From:            nakedApp,
					To:              bApp,
					Port:            90,
					Protocol:        apps.AppProtocolHTTP,
					ExpectedSuccess: true,
				},
			},
		},
	}

	for _, c := range testCases {
		namespace := c.namespace
		if len(namespace) == 0 {
			namespace = istioCfg.SystemNamespace
		}

		policy := policy.ApplyPolicyFile(t, env, namespace, c.configFile)
		// Give some time for the policy propagate.
		// TODO: query pilot or app to know instead of sleep.
		time.Sleep(time.Second)
		for _, conn := range c.connections {
			retry.UntilSuccessOrFail(t, func() error {
				return connect.CheckConnection(t, conn)
			}, retry.Delay(time.Second), retry.Timeout(10*time.Second))
		}
		policy.TearDown()
	}
}

// TestAuthentictionPermissiveE2E these cases are covered end to end
// app A to app B using plaintext (mTLS),
// app A to app B using HTTPS (mTLS),
// app A to app B using plaintext (legacy),
// app A to app B using HTTPS (legacy).
// explained: app-to-app-protocol(sidecar-to-sidecar-protocol). "legacy" means
// no client sidecar, unable to send "istio" alpn indicator.
// TODO(incfly): implement this
// func TestAuthentictionPermissiveE2E(t *testing.T) {
// Steps:
// Configure authn policy.
// Wait for config propagation.
// Send HTTP requests between apps.
// }
