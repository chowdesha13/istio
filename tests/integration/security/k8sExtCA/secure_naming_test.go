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

package k8sExtCA

import (
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/echoboot"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/util/retry"
	"istio.io/istio/tests/integration/security/util"
	"istio.io/istio/tests/integration/security/util/connection"
)

const (
	// The length of the example certificate chain.
	exampleCertChainLength = 3

	defaultIdentityDR = `apiVersion: "networking.istio.io/v1alpha3"
kind: "DestinationRule"
metadata:
  name: "service-b-dr"
spec:
  host: "b.NS.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
      subjectAltNames:
      - "spiffe://cluster.local/ns/NS/sa/default"
`
	correctIdentityDR = `apiVersion: "networking.istio.io/v1alpha3"
kind: "DestinationRule"
metadata:
  name: "service-b-dr"
spec:
  host: "b.NS.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
      subjectAltNames:
      - "spiffe://cluster.local/ns/NS/sa/b"
`
	nonExistIdentityDR = `apiVersion: "networking.istio.io/v1alpha3"
kind: "DestinationRule"
metadata:
  name: "service-b-dr"
spec:
  host: "b.NS.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
      subjectAltNames:
      - "I-do-not-exist"
`
	identityListDR = `apiVersion: "networking.istio.io/v1alpha3"
kind: "DestinationRule"
metadata:
  name: "service-b-dr"
spec:
  host: "b.NS.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
      subjectAltNames:
      - "spiffe://cluster.local/ns/NS/sa/a"
      - "spiffe://cluster.local/ns/NS/sa/b"
      - "spiffe://cluster.local/ns/default/sa/default"
      - "I-do-not-exist"
`
)

// TestSecureNaming verifies:
// - The certificate issued by CA to the sidecar is as expected and that strict mTLS works as expected.
// - The plugin CA certs are correctly used in workload mTLS.
// - The CA certificate in the configmap of each namespace is as expected, which
//   is used for data plane to control plane TLS authentication.
// - Secure naming information is respected in the mTLS handshake.
func TestSecureNaming(t *testing.T) {
	framework.NewTest(t).
		Features("security.customca.secure-naming").
		Run(func(ctx framework.TestContext) {
			istioCfg := istio.DefaultConfigOrFail(t, ctx)
			testNamespace := namespace.NewOrFail(t, ctx, namespace.Config{
				Prefix: "secure-naming",
				Inject: true,
			})
			namespace.ClaimOrFail(t, ctx, istioCfg.SystemNamespace)
			var a, b echo.Instance

			echoboot.NewBuilder(ctx).
				With(&a, util.EchoConfig("a", testNamespace, false, nil)).
				With(&b, util.EchoConfig("b", testNamespace, false, nil)).
				BuildOrFail(t)

			// TODO: Validate that the Cert in the sidecar is signed by a CA with the root-cert loaded during setup
			ctx.NewSubTest("mTLS cert validation with k8s plugin CA").
				Run(func(ctx framework.TestContext) {
					// Verify mTLS works between a and b
					callOptions := echo.CallOptions{
						Target:   b,
						PortName: "http",
						Scheme:   scheme.HTTP,
					}
					checker := connection.Checker{
						From:          a,
						Options:       callOptions,
						ExpectSuccess: true,
					}
					checker.CheckOrFail(ctx)
				})

			secureNamingTestCases := []struct {
				name            string
				destinationRule string
				expectSuccess   bool
			}{
				{
					name:            "connection fails when DR doesn't match SA",
					destinationRule: defaultIdentityDR,
					expectSuccess:   false,
				},
				{
					name:            "connection succeeds when DR matches SA",
					destinationRule: correctIdentityDR,
					expectSuccess:   true,
				},
				{
					name:            "connection fails when DR contains non-matching, non-existing SA",
					destinationRule: nonExistIdentityDR,
					expectSuccess:   false,
				},
				{
					name:            "connection succeeds when SA is in the list of SANs",
					destinationRule: identityListDR,
					expectSuccess:   true,
				},
			}
			for _, tc := range secureNamingTestCases {
				ctx.NewSubTest(tc.name).
					Run(func(ctx framework.TestContext) {
						dr := strings.ReplaceAll(tc.destinationRule, "NS", testNamespace.Name())
						ctx.Config().ApplyYAMLOrFail(t, testNamespace.Name(), dr)
						// Verify mTLS works between a and b
						callOptions := echo.CallOptions{
							Target:   b,
							PortName: "http",
							Scheme:   scheme.HTTP,
						}
						checker := connection.Checker{
							From:          a,
							Options:       callOptions,
							ExpectSuccess: tc.expectSuccess,
						}
						if err := retry.UntilSuccess(
							checker.Check, retry.Delay(time.Second), retry.Timeout(15*time.Second), retry.Converge(5)); err != nil {
							ctx.Fatal(err)
						}
					})
			}
		})
}
