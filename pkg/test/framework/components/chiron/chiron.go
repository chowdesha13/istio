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

package chiron

import (
	"time"

	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/resource"
	"istio.io/istio/pkg/test/framework/resource/environment"

	corev1 "k8s.io/api/core/v1"
)

// Instance represents a deployed Istio instance.
type Instance interface {
	resource.Resource

	WaitForSecretToExist(name string, waitTime time.Duration) (*corev1.Secret, error)
	WaitForSecretToExistOrFail(t test.Failer, name string, waitTime time.Duration) *corev1.Secret
}

type Config struct {
	Istio istio.Instance
}

// New returns a new instance of Apps
func New(ctx resource.Context, cfg Config) (i Instance, err error) {
	err = resource.UnsupportedEnvironment(ctx.Environment())

	ctx.Environment().Case(environment.Kube, func() {
		i = newKube(ctx, cfg)
		err = nil
	})

	return
}

// Deploy returns a new Istio test instance or fails the test
func NewOrFail(t test.Failer, ctx resource.Context, cfg Config) Instance {
	t.Helper()

	i, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("chiron.NewOrFail: %v", err)
	}
	return i
}
