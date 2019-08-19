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

package meshcfg

import (
	"testing"

	. "github.com/onsi/gomega"

	"istio.io/api/mesh/v1alpha1"
)

func TestDefaults(t *testing.T) {
	g := NewGomegaWithT(t)

	m := Default()

	// A couple of point-wise checks.
	g.Expect(m.IngressClass).To(Equal("istio"))
	g.Expect(m.IngressControllerMode).To(Equal(v1alpha1.MeshConfig_STRICT))
}
