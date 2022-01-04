//go:build integ
// +build integ

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

package nullvm

import (
	"testing"

	"istio.io/istio/pkg/test/framework"
	common "istio.io/istio/tests/integration/telemetry/stats/prometheus"
)

func TestAccessLogs(t *testing.T) {
	framework.NewTest(t).
		Features("observability.telemetry.logging").
		Run(func(t framework.TestContext) {
			t.NewSubTest("enabled").Run(func(t framework.TestContext) {
				applyTelemetryResource(true)
				common.RunAccessLogsTests(t, true)
			})
			t.NewSubTest("disabled").Run(func(t framework.TestContext) {
				applyTelemetryResource(false)
				common.RunAccessLogsTests(t, false)
			})
		})
}

func applyTelemetryResource(t framework.TestContext, expectLogs bool) {
	config := fmt.Sprintf(`apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: logs
spec:
  accessLogging:
  - disabled: %v
`, !expectLogs)
	t.ConfigIstio().ApplyYAMLOrFail(t, common.GetAppNamespace().Name(), config)
}
