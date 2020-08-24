package istioagent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
	"google.golang.org/grpc/reflection"

	"istio.io/pkg/log"
)

func (a *Agent) StartXdsProxy() (*XdsProxy, error) {
	l, err := setUpUds("./etc/istio/proxy/XDS")
	if err != nil {
		return nil, err
	}
	// TODO share SDS server
	grpcs := grpc.NewServer()
	proxy := &XdsProxy{
		Requests:  make(chan *discovery.DiscoveryRequest),
		Responses: make(chan *discovery.DiscoveryResponse),
	}
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcs, proxy)
	reflection.Register(grpcs)

	// TODO proper verify
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	//pcc, err := oauth.NewJWTAccessFromFile("./var/run/secrets/tokens/istio-token")
	//if err != nil {
	//	return nil, err
	//}
	log.Infof("connecting to %v", a.proxyConfig.DiscoveryAddress)
	conn, err := grpc.Dial(a.proxyConfig.DiscoveryAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(config)),
		grpc.WithPerRPCCredentials(oauth.TokenSource{&fileTokenSource{
			"./var/run/secrets/tokens/istio-token",
			time.Second * 300,
		}}),
	)
	if err != nil {
		return nil, err
	}
	xds := discovery.NewAggregatedDiscoveryServiceClient(conn)
	client, err := xds.StreamAggregatedResources(context.Background())
	if err != nil {
		return nil, err
	}
	proxy.client = client
	go func() {
		for {
			resp, err := client.Recv()
			if err != nil {
				log.Errorf("recv error: %v", err)
				return
			}
			proxy.Responses <- resp
		}
	}()
	go grpcs.Serve(l)
	return proxy, nil
}

type XdsProxy struct {
	client    discovery.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	Requests  chan *discovery.DiscoveryRequest
	Responses chan *discovery.DiscoveryResponse
}

func (p *XdsProxy) StreamAggregatedResources(server discovery.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	go func() {
		for {
			req, err := server.Recv()
			if err != nil {
				log.Errorf("recv error: %v", err)
				return
			}
			p.Requests <- req
		}
	}()
	for {
		select {
		case req := <-p.Requests:
			err := p.client.Send(req)
			log.Infof("forwarded request %v with err %v", req.TypeUrl, err)
		case resp := <-p.Responses:
			err := server.Send(resp)
			log.Infof("forwarded response %v with err %v", resp.TypeUrl, err)
		}
	}
}

func (p *XdsProxy) DeltaAggregatedResources(server discovery.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	return errors.New("delta XDS is not implemented")
}

// TODO reuse code from SDS
// TODO reuse the connection, not just code
func setUpUds(udsPath string) (net.Listener, error) {
	// Remove unix socket before use.
	if err := os.Remove(udsPath); err != nil && !os.IsNotExist(err) {
		// Anything other than "file not found" is an error.
		log.Errorf("Failed to remove unix://%s: %v", udsPath, err)
		return nil, fmt.Errorf("failed to remove unix://%s", udsPath)
	}

	// Attempt to create the folder in case it doesn't exist
	if err := os.MkdirAll(filepath.Dir(udsPath), 0750); err != nil {
		// If we cannot create it, just warn here - we will fail later if there is a real error
		log.Warnf("Failed to create directory for %v: %v", udsPath, err)
	}

	var err error
	udsListener, err := net.Listen("unix", udsPath)
	if err != nil {
		log.Errorf("Failed to listen on unix socket %q: %v", udsPath, err)
		return nil, err
	}

	// Update SDS UDS file permission so that istio-proxy has permission to access it.
	if _, err := os.Stat(udsPath); err != nil {
		log.Errorf("SDS uds file %q doesn't exist", udsPath)
		return nil, fmt.Errorf("sds uds file %q doesn't exist", udsPath)
	}
	if err := os.Chmod(udsPath, 0666); err != nil {
		log.Errorf("Failed to update %q permission", udsPath)
		return nil, fmt.Errorf("failed to update %q permission", udsPath)
	}

	return udsListener, nil
}

type fileTokenSource struct {
	path   string
	period time.Duration
}

var _ = oauth2.TokenSource(&fileTokenSource{})

func (ts *fileTokenSource) Token() (*oauth2.Token, error) {
	tokb, err := ioutil.ReadFile(ts.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file %q: %v", ts.path, err)
	}
	tok := strings.TrimSpace(string(tokb))
	if len(tok) == 0 {
		return nil, fmt.Errorf("read empty token from file %q", ts.path)
	}

	return &oauth2.Token{
		AccessToken: tok,
		Expiry:      time.Now().Add(ts.period),
	}, nil
}
