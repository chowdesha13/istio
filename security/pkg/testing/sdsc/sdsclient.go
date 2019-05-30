// Package sdsc includes a lightweight testing client to interact with SDS.
package sdsc

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"istio.io/pkg/log"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	authapi "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v2"
	"github.com/gogo/protobuf/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"istio.io/istio/pilot/pkg/model"
	sdscache "istio.io/istio/security/pkg/nodeagent/cache"
	agent_sds "istio.io/istio/security/pkg/nodeagent/sds"
)

// Client is a lightweight client for testing secret discovery service server.
type Client struct {
	stream        sds.SecretDiscoveryService_StreamSecretsClient
	conn          *grpc.ClientConn
	updateChan    chan xdsapi.DiscoveryResponse
	serverAddress string
}

// ClientOptions contains the options for the SDS testing.
type ClientOptions struct {
	// unix://var/run/sds/, localhost:15000
	// https://github.com/grpc/grpc/blob/master/doc/naming.md#name-syntax
	ServerAddress string
}

// constructSDSRequest returns the context for the outbound request to include necessary
func constructSDSRequestContext() (context.Context, error) {
	// Read from the designated location for Kubernetes JWT.
	content, err := ioutil.ReadFile(model.K8sSAJwtFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read the token file %v", err)
	}
	md := metadata.New(map[string]string{
		model.K8sSAJwtTokenHeaderKey: string(content),
	})
	return metadata.NewOutgoingContext(context.Background(), md), nil
}

// NewClient returns a sds client for testing.
func NewClient(opt ClientOptions) (*Client, error) {
	conn, err := grpc.Dial(opt.ServerAddress, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}
	client := sds.NewSecretDiscoveryServiceClient(conn)
	ctx, err := constructSDSRequestContext()
	if err != nil {
		return nil, fmt.Errorf("failed to construct the context %v", err)
	}
	stream, err := client.StreamSecrets(ctx)
	if err != nil {
		return nil, err
	}
	return &Client{
		stream:        stream,
		conn:          conn,
		updateChan:    make(chan xdsapi.DiscoveryResponse, 1),
		serverAddress: opt.ServerAddress,
	}, nil
}

// Start starts sds client to receive the scecret updates from the server.
func (c *Client) Start() {
	go func() {
		for {
			msq, err := c.stream.Recv()
			if err != nil {
				log.Errorf("Connection closed %v", err)
				return
			}
			c.updateChan <- *msq
			log.Infof("Received response from sds server %v", msq)
			if err := ValidateResponse(msq); err != nil {
				log.Errorf("Failed to validate sds response %v", err)
				return
			}
		}
	}()
}

// Stop stops the sds client.
func (c *Client) Stop() error {
	return c.stream.CloseSend()
}

// WaitForUpdate blocks until the error occurs or updates are pushed from the sds server.
func (c *Client) WaitForUpdate(duration time.Duration) (*xdsapi.DiscoveryResponse, error) {
	t := time.NewTimer(duration)
	for {
		select {
		case resp := <-c.updateChan:
			return &resp, nil
		case <-t.C:
			return nil, fmt.Errorf("timeout for updates")
		}
	}
}

// Send sends a request to the agent.
func (c *Client) Send() error {
	// TODO(incfly): just a place holder, need to follow xDS protocol.
	// - Initial request version is empty.
	// - Version & Nonce is needed for ack/rejecting.
	return c.stream.Send(&xdsapi.DiscoveryRequest{
		VersionInfo: "",
		Node: &core.Node{
			Id: "sidecar~127.0.0.1~id2~local",
		},
		ResourceNames: []string{
			sdscache.WorkloadKeyCertResourceName,
		},
		TypeUrl: agent_sds.SecretType,
	})
}

// ValidateResponse validates the SDS response.
// TODO(incfly): add more check around cert.
func ValidateResponse(response *xdsapi.DiscoveryResponse) error {
	if response == nil {
		return fmt.Errorf("discoveryResponse is empty")
	}
	if len(response.Resources) != 1 {
		return fmt.Errorf("unexpected resource size in the response, %v ", response.Resources)
	}
	var pb authapi.Secret
	if err := types.UnmarshalAny(&response.Resources[0], &pb); err != nil {
		return fmt.Errorf("unmarshalAny SDS response failed: %v", err)
	}
	return nil
}
