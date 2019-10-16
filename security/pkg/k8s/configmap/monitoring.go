// Copyright 2018 Istio Authors
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

package configmap

import "istio.io/pkg/monitoring"

var (
	extraTrustAnchorCounts = monitoring.NewGauge(
		"citadel_extra_trust_anchor_count",
		"The total number of extra trust anchors appended to the root CA cert")
)

func init() {
	monitoring.MustRegister(
		extraTrustAnchorCounts,
	)
}

// monitoringMetrics are counters for secret controller operations.
type monitoringMetrics struct {
	extraTrustAnchors monitoring.Metric
}

// newMonitoringMetrics creates a new monitoringMetrics.
func newMonitoringMetrics() monitoringMetrics {
	return monitoringMetrics{
		extraTrustAnchors: extraTrustAnchorCounts,
	}
}
