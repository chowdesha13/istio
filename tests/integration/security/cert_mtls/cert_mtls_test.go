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

package certmtls

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/echoboot"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource/environment"
	"istio.io/istio/tests/integration/security/util"
	"istio.io/istio/tests/integration/security/util/cert"
	"istio.io/istio/tests/integration/security/util/connection"
)

var (
	testNamespace namespace.Instance
	testCtx       framework.TestContext
	testStruct    *testing.T
)

// TestCertMtls verifiess that the certificate issued by CA to the sidecar
// is as expected and strict mTLS works as expected.
func TestCertMtls(t *testing.T) {
	framework.NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			istioCfg := istio.DefaultConfigOrFail(t, ctx)

			namespace.ClaimOrFail(t, ctx, istioCfg.SystemNamespace)
			testNamespace = namespace.NewOrFail(t, ctx, namespace.Config{
				Prefix: "test-cert-mtls",
				Inject: true,
			})
			testCtx = ctx
			testStruct = t

			// Enforce strict mTLS for app b
			var a, b echo.Instance
			appName := "b"
			policyYAML := fmt.Sprintf(`apiVersion: "security.istio.io/v1beta1"
kind: "PeerAuthentication"
metadata:
  name: "mtls-strict-for-%v"
spec:
  selector:
    matchLabels:
      app: "%v"
  mtls:
    mode: STRICT
`, appName, appName)
			g.ApplyConfigOrFail(t, testNamespace, policyYAML)
			echoboot.NewBuilderOrFail(ctx, ctx).
				With(&a, util.EchoConfig("a", testNamespace, false, nil, g, p)).
				With(&b, util.EchoConfig("b", testNamespace, false, nil, g, p)).
				BuildOrFail(t)

			// Verify that the certificate issued to the sidecar is as expected.
			connectTarget := fmt.Sprintf("b.%s:80", testNamespace.Name())
			out, err := cert.GetCertOutput(testNamespace, "app=a", "istio-proxy",
				connectTarget)
			if err != nil {
				t.Errorf("GetCertOutput() returns an error: %v", err)
				return
			}
			var certExp = regexp.MustCompile("(?sU)-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----")
			certs := certExp.FindAll([]byte(out), -1)
			// Verify that the certificate chain length is as expected
			if len(certs) != 3 {
				t.Errorf("expect 3 certs in the cert chain but getting %v certs", len(certs))
				return
			}
			var rootCert []byte
			if rootCert, err = cert.ReadSampleCertFile("root-cert.pem"); err != nil {
				t.Errorf("error when reading expected CA cert: %v", err)
				return
			}
			// Verify that the CA certificate is as expected
			if strings.TrimSpace(string(rootCert)) != strings.TrimSpace(string(certs[2])) {
				t.Errorf("the actual CA cert is different from the expected. expected: %v, actual: %v",
					strings.TrimSpace(string(rootCert)), strings.TrimSpace(string(certs[2])))
				return
			}
			t.Log("the CA certificate is as expected")

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
			t.Log("mTLS check passed")
		})
}
