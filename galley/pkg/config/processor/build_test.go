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

package processor

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"istio.io/istio/galley/pkg/config/event"
	"istio.io/istio/galley/pkg/config/meshcfg"
	"istio.io/istio/galley/pkg/config/processing/monitoring"
	"istio.io/istio/galley/pkg/config/processing/snapshotter"
	"istio.io/istio/galley/pkg/config/processor/metadata"
	"istio.io/istio/galley/pkg/config/source/kube/inmemory"
)

const yml = `
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: helloworld-gateway
spec:
  selector:
    istio: ingressgateway # use istio default controller
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "*"

`

func TestProcessor(t *testing.T) {
	g := NewGomegaWithT(t)

	meshSrc := meshcfg.NewInmemory()
	src := inmemory.NewKube(metadata.MustGet().KubeSource().Resources())
	srcs := []event.Source{
		meshSrc,
		src,
	}

	meshSrc.Set(meshcfg.Default())
	distributor := snapshotter.NewInMemoryDistributor()

	rt, err := Initialize(metadata.MustGet(), "svc.local", srcs, distributor, &monitoring.NoopReporter{})
	g.Expect(err).To(BeNil())

	rt.Start()

	err = src.ApplyContent("foo", yml)
	g.Expect(err).To(BeNil())

	time.Sleep(time.Second)
	_ = distributor.GetSnapshot("default")
}
