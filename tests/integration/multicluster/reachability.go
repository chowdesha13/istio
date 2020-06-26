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

package multicluster

import (
	"fmt"
	"testing"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/echoboot"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/features"
	"istio.io/istio/pkg/test/framework/label"
)

// ReachabilityTest tests that services in 2 different clusters can talk to each other.
func ReachabilityTest(t *testing.T, ns namespace.Instance, feature features.Feature) {
	framework.NewTest(t).
		Label(label.Multicluster).
		Features(feature).
		Run(func(ctx framework.TestContext) {
			ctx.NewSubTest("reachability").
				Run(func(ctx framework.TestContext) {
					clusters := ctx.Clusters()
					// Running multiple instances in each cluster teases out cases where proxies inconsistently
					// use wrong different discovery server. For higher numbers of clusters, we already end up
					// running plenty of services. (see https://github.com/istio/istio/issues/23591).
					svcPerCluster := 5 - len(clusters)
					if svcPerCluster < 1 {
						svcPerCluster = 1
					}

					builder := echoboot.NewBuilder(ctx)
					for _, cluster := range clusters {
						for i := 0; i < svcPerCluster; i++ {
							svcName := fmt.Sprintf("echo-%d-%d", cluster.Index(), i)
							builder = builder.With(nil, newEchoConfig(svcName, ns, cluster))
						}
					}
					echos := builder.BuildOrFail(ctx)

					// Now verify that all services in each cluster can hit one service in each cluster.
					// Calling 1 service per remote cluster makes the number linear rather than quadratic with
					// respect to len(clusters) * svcPerCluster.
					for _, src := range echos {
						for _, dstCluster := range clusters {
							src := src
							dest := echos.GetOrFail(ctx, echo.InCluster(dstCluster))
							subTestName := fmt.Sprintf("%s->%s://%s:%s%s",
								src.Config().Service,
								"http",
								dest.Config().Service,
								"http",
								"/")
							ctx.NewSubTest(subTestName).
								RunParallel(func(ctx framework.TestContext) {
									_ = callOrFail(ctx, src, dest)
								})
						}
					}
				})
		})
}
