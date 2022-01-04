//go:build integ
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

package prometheus

import (
	"fmt"
	"strings"
	"time"

	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/util/retry"
	"istio.io/istio/tests/integration/security/util"
	testutils "istio.io/istio/tests/util"
)

func RunAccessLogsTests(t framework.TestContext, expectLogs bool) {
	testID := testutils.RandomString(16)
	if expectLogs {
		// For positive test, we use the same ID and repeatedly send requests and check the count
		retry.UntilSuccessOrFail(t, func() error {
			GetClientInstances()[0].CallWithRetryOrFail(t, echo.CallOptions{
				Target:   GetServerInstances()[0],
				PortName: "http",
				Count:    util.CallsPerCluster * len(GetServerInstances().Clusters()),
				Path:     "/" + testID,
			})
			// Retry a bit to get the logs. There is some delay before they are output, so they may not be immediately ready
			// If not ready in 5s, we retry sending a call again.
			retry.UntilSuccessOrFail(t, func() error {
				count := LogCount(t, GetServerInstances(), testID)
				if count > 0 != expectLogs {
					return fmt.Errorf("expected logs '%v', got %v", expectLogs, count)
				}
				return nil
			}, retry.Timeout(time.Second*5))
			return nil
		})
	} else {
		// For negative case, we retry with a new ID each time. This ensures that a previous failure
		// (due to hitting old code path with logs still enabled) doesn't stop us from succeeding later
		// once we stop logging.
		retry.UntilSuccessOrFail(t, func() error {
			testID := testutils.RandomString(16)
			GetClientInstances()[0].CallWithRetryOrFail(t, echo.CallOptions{
				Target:   GetServerInstances()[0],
				PortName: "http",
				Count:    util.CallsPerCluster * len(GetServerInstances().Clusters()),
				Path:     "/" + testID,
			})
			// This is a negative test; there isn't much we can do other than wait a few seconds and ensure we didn't emit logs
			// Logs should flush every 1s, so 2s should be plenty of time for logs to be emitted
			time.Sleep(time.Second * 2)
			count := LogCount(t, GetServerInstances(), testID)
			if count > 0 != expectLogs {
				return fmt.Errorf("expected logs '%v', got %v", expectLogs, count)
			}
			return nil
		})
	}
}

func LogCount(t test.Failer, instances echo.Instances, testID string) float64 {
	counts := map[string]float64{}
	for _, instance := range instances {
		workloads, err := instance.Workloads()
		if err != nil {
			t.Fatalf("failed to get Subsets: %v", err)
		}
		var logs string
		for _, w := range workloads {
			l, err := w.Sidecar().Logs()
			if err != nil {
				t.Fatalf("failed getting logs: %v", err)
			}
			logs += l
		}
		if c := float64(strings.Count(logs, testID)); c > 0 {
			counts[instance.Config().Cluster.Name()] = c
		}
	}
	var total float64
	for _, c := range counts {
		total += c
	}
	return total
}
