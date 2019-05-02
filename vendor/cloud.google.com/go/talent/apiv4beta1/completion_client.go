// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gapic-generator. DO NOT EDIT.

package talent

import (
	"context"
	"fmt"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
	talentpb "google.golang.org/genproto/googleapis/cloud/talent/v4beta1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// CompletionCallOptions contains the retry settings for each method of CompletionClient.
type CompletionCallOptions struct {
	CompleteQuery []gax.CallOption
}

func defaultCompletionClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint("jobs.googleapis.com:443"),
		option.WithScopes(DefaultAuthScopes()...),
	}
}

func defaultCompletionCallOptions() *CompletionCallOptions {
	retry := map[[2]string][]gax.CallOption{
		{"default", "idempotent"}: {
			gax.WithRetry(func() gax.Retryer {
				return gax.OnCodes([]codes.Code{
					codes.DeadlineExceeded,
					codes.Unavailable,
				}, gax.Backoff{
					Initial:    100 * time.Millisecond,
					Max:        60000 * time.Millisecond,
					Multiplier: 1.3,
				})
			}),
		},
	}
	return &CompletionCallOptions{
		CompleteQuery: retry[[2]string{"default", "idempotent"}],
	}
}

// CompletionClient is a client for interacting with Cloud Talent Solution API.
//
// Methods, except Close, may be called concurrently. However, fields must not be modified concurrently with method calls.
type CompletionClient struct {
	// The connection to the service.
	conn *grpc.ClientConn

	// The gRPC API client.
	completionClient talentpb.CompletionClient

	// The call options for this service.
	CallOptions *CompletionCallOptions

	// The x-goog-* metadata to be sent with each request.
	xGoogMetadata metadata.MD
}

// NewCompletionClient creates a new completion client.
//
// A service handles auto completion.
func NewCompletionClient(ctx context.Context, opts ...option.ClientOption) (*CompletionClient, error) {
	conn, err := transport.DialGRPC(ctx, append(defaultCompletionClientOptions(), opts...)...)
	if err != nil {
		return nil, err
	}
	c := &CompletionClient{
		conn:        conn,
		CallOptions: defaultCompletionCallOptions(),

		completionClient: talentpb.NewCompletionClient(conn),
	}
	c.setGoogleClientInfo()
	return c, nil
}

// Connection returns the client's connection to the API service.
func (c *CompletionClient) Connection() *grpc.ClientConn {
	return c.conn
}

// Close closes the connection to the API service. The user should invoke this when
// the client is no longer required.
func (c *CompletionClient) Close() error {
	return c.conn.Close()
}

// setGoogleClientInfo sets the name and version of the application in
// the `x-goog-api-client` header passed on each request. Intended for
// use by Google-written clients.
func (c *CompletionClient) setGoogleClientInfo(keyval ...string) {
	kv := append([]string{"gl-go", versionGo()}, keyval...)
	kv = append(kv, "gapic", versionClient, "gax", gax.Version, "grpc", grpc.Version)
	c.xGoogMetadata = metadata.Pairs("x-goog-api-client", gax.XGoogHeader(kv...))
}

// CompleteQuery completes the specified prefix with keyword suggestions.
// Intended for use by a job search auto-complete search box.
func (c *CompletionClient) CompleteQuery(ctx context.Context, req *talentpb.CompleteQueryRequest, opts ...gax.CallOption) (*talentpb.CompleteQueryResponse, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "parent", req.GetParent()))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.CompleteQuery[0:len(c.CallOptions.CompleteQuery):len(c.CallOptions.CompleteQuery)], opts...)
	var resp *talentpb.CompleteQueryResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.completionClient.CompleteQuery(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
