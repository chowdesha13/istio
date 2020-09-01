// +build integ
// Copyright Istio Authors. All Rights Reserved.
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
	"istio.io/istio/pkg/test/framework/resource"
	"testing"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/features"
	"istio.io/istio/pkg/test/framework/label"
	common "istio.io/istio/tests/integration/telemetry/stats/prometheus/http"
)

// TestStatsFilter verifies the stats filter could emit expected client and server side metrics.
// This test focuses on stats filter and metadata exchange filter could work coherently with
// proxy bootstrap config. To avoid flake, it does not verify correctness of metrics, which
// should be covered by integration test in proxy repo.
func TestStatsFilter(t *testing.T) {
	common.TestStatsFilter(t, features.Feature("observability.telemetry.stats.prometheus.http.nullvm"))
}

func TestMain(m *testing.M) {
	framework.NewSuite(m).
		RequireSingleCluster().
		Label(label.CustomSetup).
		Setup(istio.Setup(common.GetIstioInstance(), setupConfig)).
		Setup(common.TestSetup).
		Run()
}

func setupConfig(_ resource.Context, cfg *istio.Config) {
	if cfg == nil {
		return
	}
	// enable telemetry v2 with nullvm
	cfg.Values["telemetry.v2.metadataExchange.wasmEnabled"] = "false"
	cfg.Values["telemetry.v2.prometheus.wasmEnabled"] = "false"
}
