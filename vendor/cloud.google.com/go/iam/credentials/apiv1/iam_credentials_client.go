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

package credentials

import (
	"context"
	"fmt"
	"time"

	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
	credentialspb "google.golang.org/genproto/googleapis/iam/credentials/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// IamCredentialsCallOptions contains the retry settings for each method of IamCredentialsClient.
type IamCredentialsCallOptions struct {
	GenerateAccessToken                []gax.CallOption
	GenerateIdToken                    []gax.CallOption
	SignBlob                           []gax.CallOption
	SignJwt                            []gax.CallOption
	GenerateIdentityBindingAccessToken []gax.CallOption
}

func defaultIamCredentialsClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint("iamcredentials.googleapis.com:443"),
		option.WithScopes(DefaultAuthScopes()...),
	}
}

func defaultIamCredentialsCallOptions() *IamCredentialsCallOptions {
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
	return &IamCredentialsCallOptions{
		GenerateAccessToken:                retry[[2]string{"default", "idempotent"}],
		GenerateIdToken:                    retry[[2]string{"default", "idempotent"}],
		SignBlob:                           retry[[2]string{"default", "idempotent"}],
		SignJwt:                            retry[[2]string{"default", "idempotent"}],
		GenerateIdentityBindingAccessToken: retry[[2]string{"default", "idempotent"}],
	}
}

// IamCredentialsClient is a client for interacting with IAM Service Account Credentials API.
//
// Methods, except Close, may be called concurrently. However, fields must not be modified concurrently with method calls.
type IamCredentialsClient struct {
	// The connection to the service.
	conn *grpc.ClientConn

	// The gRPC API client.
	iamCredentialsClient credentialspb.IAMCredentialsClient

	// The call options for this service.
	CallOptions *IamCredentialsCallOptions

	// The x-goog-* metadata to be sent with each request.
	xGoogMetadata metadata.MD
}

// NewIamCredentialsClient creates a new iam credentials client.
//
// A service account is a special type of Google account that belongs to your
// application or a virtual machine (VM), instead of to an individual end user.
// Your application assumes the identity of the service account to call Google
// APIs, so that the users aren't directly involved.
//
// Service account credentials are used to temporarily assume the identity
// of the service account. Supported credential types include OAuth 2.0 access
// tokens, OpenID Connect ID tokens, self-signed JSON Web Tokens (JWTs), and
// more.
func NewIamCredentialsClient(ctx context.Context, opts ...option.ClientOption) (*IamCredentialsClient, error) {
	conn, err := transport.DialGRPC(ctx, append(defaultIamCredentialsClientOptions(), opts...)...)
	if err != nil {
		return nil, err
	}
	c := &IamCredentialsClient{
		conn:        conn,
		CallOptions: defaultIamCredentialsCallOptions(),

		iamCredentialsClient: credentialspb.NewIAMCredentialsClient(conn),
	}
	c.setGoogleClientInfo()
	return c, nil
}

// Connection returns the client's connection to the API service.
func (c *IamCredentialsClient) Connection() *grpc.ClientConn {
	return c.conn
}

// Close closes the connection to the API service. The user should invoke this when
// the client is no longer required.
func (c *IamCredentialsClient) Close() error {
	return c.conn.Close()
}

// setGoogleClientInfo sets the name and version of the application in
// the `x-goog-api-client` header passed on each request. Intended for
// use by Google-written clients.
func (c *IamCredentialsClient) setGoogleClientInfo(keyval ...string) {
	kv := append([]string{"gl-go", versionGo()}, keyval...)
	kv = append(kv, "gapic", versionClient, "gax", gax.Version, "grpc", grpc.Version)
	c.xGoogMetadata = metadata.Pairs("x-goog-api-client", gax.XGoogHeader(kv...))
}

// GenerateAccessToken generates an OAuth 2.0 access token for a service account.
func (c *IamCredentialsClient) GenerateAccessToken(ctx context.Context, req *credentialspb.GenerateAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateAccessTokenResponse, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "name", req.GetName()))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.GenerateAccessToken[0:len(c.CallOptions.GenerateAccessToken):len(c.CallOptions.GenerateAccessToken)], opts...)
	var resp *credentialspb.GenerateAccessTokenResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.iamCredentialsClient.GenerateAccessToken(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GenerateIdToken generates an OpenID Connect ID token for a service account.
func (c *IamCredentialsClient) GenerateIdToken(ctx context.Context, req *credentialspb.GenerateIdTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateIdTokenResponse, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "name", req.GetName()))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.GenerateIdToken[0:len(c.CallOptions.GenerateIdToken):len(c.CallOptions.GenerateIdToken)], opts...)
	var resp *credentialspb.GenerateIdTokenResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.iamCredentialsClient.GenerateIdToken(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// SignBlob signs a blob using a service account's system-managed private key.
func (c *IamCredentialsClient) SignBlob(ctx context.Context, req *credentialspb.SignBlobRequest, opts ...gax.CallOption) (*credentialspb.SignBlobResponse, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "name", req.GetName()))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.SignBlob[0:len(c.CallOptions.SignBlob):len(c.CallOptions.SignBlob)], opts...)
	var resp *credentialspb.SignBlobResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.iamCredentialsClient.SignBlob(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// SignJwt signs a JWT using a service account's system-managed private key.
func (c *IamCredentialsClient) SignJwt(ctx context.Context, req *credentialspb.SignJwtRequest, opts ...gax.CallOption) (*credentialspb.SignJwtResponse, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "name", req.GetName()))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.SignJwt[0:len(c.CallOptions.SignJwt):len(c.CallOptions.SignJwt)], opts...)
	var resp *credentialspb.SignJwtResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.iamCredentialsClient.SignJwt(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GenerateIdentityBindingAccessToken exchange a JWT signed by third party identity provider to an OAuth 2.0
// access token
func (c *IamCredentialsClient) GenerateIdentityBindingAccessToken(ctx context.Context, req *credentialspb.GenerateIdentityBindingAccessTokenRequest, opts ...gax.CallOption) (*credentialspb.GenerateIdentityBindingAccessTokenResponse, error) {
	md := metadata.Pairs("x-goog-request-params", fmt.Sprintf("%s=%v", "name", req.GetName()))
	ctx = insertMetadata(ctx, c.xGoogMetadata, md)
	opts = append(c.CallOptions.GenerateIdentityBindingAccessToken[0:len(c.CallOptions.GenerateIdentityBindingAccessToken):len(c.CallOptions.GenerateIdentityBindingAccessToken)], opts...)
	var resp *credentialspb.GenerateIdentityBindingAccessTokenResponse
	err := gax.Invoke(ctx, func(ctx context.Context, settings gax.CallSettings) error {
		var err error
		resp, err = c.iamCredentialsClient.GenerateIdentityBindingAccessToken(ctx, req, settings.GRPC...)
		return err
	}, opts...)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
