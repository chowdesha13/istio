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

package informermetric

import (
	"sync"

	"istio.io/pkg/log"
	"istio.io/pkg/monitoring"
	"k8s.io/client-go/tools/cache"
)

var (
	clusterLabel = monitoring.MustCreateLabel("cluster")

	errorMetric = monitoring.NewSum(
		"controller_sync_errors",
		"Total number of errorMetric syncing controllers.",
	)

	mu       sync.RWMutex
	handlers = map[string]cache.WatchErrorHandler{}
)

// ErrorHandlerForCluster fetches or creates an ErrorHandler that emits a metric
// and logs when a watch error occurs. For use with SetWatchErrorHandler on SharedInformer.
func ErrorHandlerForCluster(clusterID string) cache.WatchErrorHandler {
	mu.RLock()
	handler, ok := handlers[clusterID]
	mu.RUnlock()
	if ok {
		return handler
	}

	mu.Lock()
	defer mu.Unlock()
	metric := errorMetric.With(clusterLabel.Value(clusterID))
	if err := metric.Register(); err != nil {
		log.Warnf("failed registering metric %s: %v", metric.Name(), err)
	}
	h := func(_ *cache.Reflector, err error) {
		metric.Increment()
		log.Errorf("watch error in cluster %s: %v", clusterID, err)
	}
	handlers[clusterID] = h
	return h
}
