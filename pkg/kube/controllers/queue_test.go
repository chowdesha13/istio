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

package controllers

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/atomic"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/test/util/retry"
)

func TestQueue(t *testing.T) {
	handles := atomic.NewInt32(0)
	q := NewQueue("custom", WithReconciler(func(key types.NamespacedName) error {
		handles.Inc()
		return nil
	}))
	q.Add(types.NamespacedName{Name: "something"})
	stop := make(chan struct{})
	go q.Run(stop)
	retry.UntilOrFail(t, q.HasSynced, retry.Delay(time.Microsecond))
	assert.Equal(t, handles.Load(), 1)
	q.Add(types.NamespacedName{Name: "something else"})
	close(stop)
	assert.NoError(t, q.WaitForClose(time.Second))
	// event 2 is guaranteed to happen from WaitForClose
	assert.Equal(t, handles.Load(), 2)
}

func TestQueueWithStartupBoost(t *testing.T) {
	const presync = 10
	handles := atomic.NewInt32(0)
	var wg sync.WaitGroup
	wg.Add(presync)
	q := NewQueue("custom", WithStartupBoost(), WithReconciler(func(key types.NamespacedName) error {
		handles.Inc()
		if strings.HasPrefix(key.Name, "presync-") {
			wg.Done()
			wg.Wait()
		}
		return nil
	}))
	for i := 0; i < presync; i++ {
		q.Add(types.NamespacedName{Name: fmt.Sprintf("%d", i)})
	}
	stop := make(chan struct{})
	go q.Run(stop)
	retry.UntilOrFail(t, q.HasSynced, retry.Delay(time.Microsecond))
	assert.Equal(t, handles.Load(), presync)
	q.Add(types.NamespacedName{Name: "aftersync-0"})
	close(stop)
	assert.NoError(t, q.WaitForClose(time.Second))
	assert.Equal(t, handles.Load(), presync+1)
}
