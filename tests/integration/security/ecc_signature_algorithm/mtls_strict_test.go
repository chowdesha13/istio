package eccsignaturealgorithm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/util/tmpl"
	"istio.io/istio/tests/integration/security/util"
	"istio.io/istio/tests/integration/security/util/cert"
	"testing"
)

const (
	DestinationRuleConfigIstioMutual = `
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: server
  namespace: {{.AppNamespace}}
spec:
  host: "server.{{.AppNamespace}}.svc.cluster.local"
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
`

	PeerAuthenticationConfig = `
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: {{.AppNamespace}}
spec:
  mtls:
    mode: STRICT
`
)

func TestStrictMTLS(t *testing.T) {
	framework.
		NewTest(t).
		Features("security.ecc_signature_algorithm").
		Run(func(ctx framework.TestContext) {
			peerTemplate := tmpl.EvaluateOrFail(ctx, PeerAuthenticationConfig, map[string]string{"AppNamespace": apps.Namespace.Name()})
			ctx.Config().ApplyYAMLOrFail(ctx, apps.Namespace.Name(), peerTemplate)
			ctx.WhenDone(func() error {
				return ctx.Config().DeleteYAML(apps.Namespace.Name(), peerTemplate)
			})
			util.WaitForConfigWithSleep(ctx, peerTemplate, apps.Namespace)

			drTemplate := tmpl.EvaluateOrFail(ctx, DestinationRuleConfigIstioMutual, map[string]string{"AppNamespace": apps.Namespace.Name()})
			ctx.Config().ApplyYAMLOrFail(ctx, apps.Namespace.Name(), drTemplate)
			ctx.WhenDone(func() error {
				return ctx.Config().DeleteYAML(apps.Namespace.Name(), drTemplate)
			})
			util.WaitForConfigWithSleep(ctx, drTemplate, apps.Namespace)

			response := apps.Client.CallOrFail(t, echo.CallOptions{
				Target:   apps.Server,
				PortName: "http",
				Scheme:   scheme.HTTP,
				Count:    1,
			})

			if err := response.CheckOK(); err != nil {
				ctx.Fatalf("client could not reach server: %v", err)
			}

			target := fmt.Sprintf("server.%s:8091", apps.Namespace.Name())
			certPEM, err := cert.DumpCertFromSidecar(apps.Namespace, "app=client", "istio-proxy", target)
			if err != nil {
				ctx.Fatalf("client could not get certificate from server: %v", err)
			}
			block, _ := pem.Decode([]byte(certPEM))
			if block == nil {
				ctx.Fatalf("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				ctx.Fatalf("failed to parse certificate: %v", err)
			}

			if cert.PublicKeyAlgorithm != x509.ECDSA {
				ctx.Fatalf("public key used in server cert is not ECDSA: %v", cert.PublicKeyAlgorithm)
			}
		})
}
