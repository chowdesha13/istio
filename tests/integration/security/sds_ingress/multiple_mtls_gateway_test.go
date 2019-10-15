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

package sdsingress

import (
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/environment"
	"istio.io/istio/pkg/test/framework/components/ingress"
	ingressutil "istio.io/istio/tests/integration/security/sds_ingress/util"

	"testing"
)

// testMultiMtlsGateways deploys multiple mTLS gateways with SDS enabled, and creates kubernetes that store
// private key, server certificate and CA certificate for each mTLS gateway. Verifies that all gateways are able to terminate
// mTLS connections successfully.
func testMultiMtlsGateways(t *testing.T, ctx framework.TestContext) { // nolint:interfacer
	t.Helper()

	ingressutil.CreateIngressKubeSecret(t, ctx, credNames, ingress.Mtls, ingressutil.IngressCredentialA)
	ingressutil.DeployBookinfo(t, ctx, g, ingressutil.MultiMTLSGateway)

	ing := ingress.NewOrFail(t, ctx, ingress.Config{
		Istio: inst,
	})

	tlsContext := ingressutil.TLSContext{
		CaCert:     ingressutil.CaCertA,
		PrivateKey: ingressutil.TLSClientKeyA,
		Cert:       ingressutil.TLSClientCertA,
	}
	callType := ingress.Mtls

	for _, h := range hosts {
		err := ingressutil.VisitProductPage(ing, h, callType, tlsContext, 90*time.Second,
			ingressutil.ExpectedResponse{ResponseCode: 200, ErrorMessage: ""}, t)
		if err != nil {
			t.Errorf("unable to retrieve 200 from product page at host %s: %v", h, err)
		}
	}
}

func TestMtlsGateways(t *testing.T) {
	framework.
		NewTest(t).
		RequiresEnvironment(environment.Kube).
		Run(func(ctx framework.TestContext) {
			testMultiMtlsGateways(t, ctx)
		})
}
