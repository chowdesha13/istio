package grpcgen_test

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"istio.io/istio/pkg/test/echo/proto"
	"math"
	"net"
	"testing"

	//  To install the xds resolvers and balancers.
	_ "google.golang.org/grpc/xds"

	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/xds"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/schema/collections"
	"istio.io/istio/pkg/test/echo/client"
	"istio.io/istio/pkg/test/echo/common"
	"istio.io/istio/pkg/test/echo/server/endpoint"
)

var (
	grpcEchoHostFmt = "127.0.0.%s"
)

type echoCfg struct {
	version   string
	namespace string
}

type configGenTest struct {
	*testing.T
	endpoints []endpoint.Instance
	ds        *xds.FakeDiscoveryServer
}

// newConfigGenTest creates a FakeDiscoveryServer that listens for gRPC on grpcXdsAddr
// For each of the given servers, we serve echo (only supporting Echo, no ForwardEcho) and
// create a corresponding WorkloadEntry. The WorkloadEntry will have the given format:
//
//    meta:
//      name: echo-{generated portnum}-{server.version}
//      namespace: {server.namespace or "default"}
//      labels: {"app": "grpc", "version": "{server.version}"}
//    spec:
//      address: {grpcEchoHost}
//      ports:
//        grpc: {generated portnum}
func newConfigGenTest(t *testing.T, discoveryOpts xds.FakeOptions, servers ...echoCfg) *configGenTest {
	cgt := &configGenTest{T: t}
	port := 14058
	for i, s := range servers {
		// TODO this breaks without extra ifonfig aliases on OSX, and probably elsewhere
		host := fmt.Sprintf("127.0.0.%d", i+1)
		ep, err := endpoint.New(endpoint.Config{
			IsServerReady: func() bool { return true },
			Port:          &common.Port{Name: "grpc", Port: port, Protocol: protocol.GRPC},
			ListenerIP:    host,
			Version:       s.version,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := ep.Start(func() {}); err != nil {
			t.Fatal(err)
		}
		cgt.endpoints = append(cgt.endpoints, ep)
		discoveryOpts.Configs = append(discoveryOpts.Configs, makeWE(s, host, port))
		port++
	}

	discoveryOpts.ListenerBuilder = func() (net.Listener, error) {
		return net.Listen("tcp", grpcXdsAddr)
	}
	cgt.ds = xds.NewFakeDiscoveryServer(t, discoveryOpts)
	return cgt
}

func makeWE(s echoCfg, host string, port int) config.Config {
	ns := "default"
	if s.namespace != "" {
		ns = s.namespace
	}
	return config.Config{
		Meta: config.Meta{
			Name:             fmt.Sprintf("echo-%d-%s", port, s.version),
			Namespace:        ns,
			GroupVersionKind: collections.IstioNetworkingV1Alpha3Workloadentries.Resource().GroupVersionKind(),
			Labels: map[string]string{
				"app":     "echo",
				"version": s.version,
			},
		},
		Spec: &networking.WorkloadEntry{
			Address: host,
			Ports:   map[string]uint32{"grpc": uint32(port)},
		},
	}
}

func (t *configGenTest) dialEcho(addr string) *client.Instance {
	resolver := resolverForTest(t)
	out, err := client.New(addr, nil, grpc.WithResolvers(resolver))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGrpcVirtualService(t *testing.T) {
	tt := newConfigGenTest(t, xds.FakeOptions{
		KubernetesObjectString: `
apiVersion: v1
kind: Service
metadata:
  labels:
    app: echo-app
  name: echo-app
  namespace: default
spec:
  clusterIP: 1.2.3.4
  selector:
    app: echo
  ports:
  - name: grpc
    port: 7070
`,
		ConfigString: `
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: echo-dr
  namespace: default
spec:
  host: echo-app.default.svc.cluster.local
  subsets:
    - name: v1
      labels:
        version: v1
    - name: v2
      labels:
        version: v2
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: echo-vs
  namespace: default
spec:
  hosts:
  - echo-app.default.svc.cluster.local
  http:
  - route:
    - destination:
        host: echo-app.default.svc.cluster.local
        subset: v1
      weight: 20
    - destination:
        host: echo-app.default.svc.cluster.local
        subset: v2
      weight: 80

`,
	}, echoCfg{version: "v1"}, echoCfg{version: "v2"})
	cw := tt.dialEcho("xds:///echo-app.default.svc.cluster.local:7070")

	distribution := map[string]int{}

	for i := 0; i < 100; i++ {
		res, err := cw.Echo(context.Background(), &proto.EchoRequest{Message: "needle"})
		if err != nil {
			t.Fatal(err)
		}
		distribution[res.Version]++
	}

	if err := expectAlmost(distribution["v1"], 20); err != nil {
		t.Fatal(err)
	}
	if err := expectAlmost(distribution["v2"], 80); err != nil {
		t.Fatal(err)
	}
}

func expectAlmost(got, want int) error {
	if math.Abs(float64(want-got)) > 10 {
		return fmt.Errorf("expected ~%d but got %d", want, got)
	}
	return nil
}
