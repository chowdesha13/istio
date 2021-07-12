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

package caclient

import (
	"context"
	"fmt"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"google.golang.org/api/option"
	privatecapb "google.golang.org/genproto/googleapis/cloud/security/privateca/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"k8s.io/apimachinery/pkg/util/rand"

	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/nodeagent/caclient"
	"istio.io/istio/security/pkg/nodeagent/caclient/providers/google-cas/mock"
	"istio.io/pkg/log"
)

var googleCAClientLog = log.RegisterScope("googlecas", "Google CAS client debugging", 0)

// GoogleCASClient: Agent side plugin for Google CAS
type GoogleCASClient struct {
	caSigner string
	caClient *privateca.CertificateAuthorityClient
	provider *caclient.TokenProvider
}

// NewGoogleCASClient create a CA client for Google CAS.
func NewGoogleCASClient(capool string, provider *caclient.TokenProvider, lis *bufconn.Listener) (security.Client, error) {
	var err error
	caClient := &GoogleCASClient{caSigner: capool, provider: provider}
	ctx := context.Background()

	if lis == nil {
		caClient.caClient, err = privateca.NewCertificateAuthorityClient(ctx,
			option.WithGRPCDialOption(grpc.WithPerRPCCredentials(provider)))
	} else {
		// For Unit Testing
		caClient.caClient, err = privateca.NewCertificateAuthorityClient(ctx,
			option.WithoutAuthentication(),
			option.WithGRPCDialOption(grpc.WithContextDialer(mock.ContextDialerCreate(lis))),
			option.WithGRPCDialOption(grpc.WithInsecure()))
	}
	if err != nil {
		googleCAClientLog.Errorf("unable to initialize google cas caclient: %v", err)
		return nil, err
	}
	googleCAClientLog.Debugf("Intitialized Google CAS plugin with endpoint: %v", capool)
	return caClient, nil
}

func (r *GoogleCASClient) createCertReq(name string, csrPEM []byte, lifetime time.Duration) *privatecapb.CreateCertificateRequest {
	var isCA bool = false

	// We use Certificate_Config option to ensure that we only request a certificate with CAS supported extensions/usages.
	// CAS uses the PEM encoded CSR only for its public key and infers the certificate SAN (identity) of the workload through SPIFFE identity reflection
	creq := &privatecapb.CreateCertificateRequest{
		Parent:        r.caSigner,
		CertificateId: name,
		Certificate: &privatecapb.Certificate{
			Lifetime: durationpb.New(lifetime),
			CertificateConfig: &privatecapb.Certificate_Config{
				Config: &privatecapb.CertificateConfig{
					X509Config: &privatecapb.X509Parameters{
						KeyUsage: &privatecapb.KeyUsage{
							BaseKeyUsage: &privatecapb.KeyUsage_KeyUsageOptions{
								DigitalSignature: true,
								KeyEncipherment:  true,
							},
							ExtendedKeyUsage: &privatecapb.KeyUsage_ExtendedKeyUsageOptions{
								ServerAuth: true,
								ClientAuth: true,
							},
						},
						CaOptions: &privatecapb.X509Parameters_CaOptions{
							IsCa: &isCA,
						},
					},
					PublicKey: &privatecapb.PublicKey{
						Format: privatecapb.PublicKey_PEM,
						Key:    csrPEM,
					},
				},
			},
			SubjectMode: privatecapb.SubjectRequestMode_REFLECTED_SPIFFE,
		},
	}
	return creq
}

// CSR Sign calls Google CAS to sign a CSR.
func (r *GoogleCASClient) CSRSign(csrPEM []byte, certValidTTLInSec int64) ([]string, error) {
	certChain := []string{}
	name := fmt.Sprintf("csr-workload-%s", rand.String(8))
	creq := r.createCertReq(name, csrPEM, time.Duration(certValidTTLInSec)*time.Second)

	ctx := context.Background()

	cresp, err := r.caClient.CreateCertificate(ctx, creq)
	if err != nil {
		googleCAClientLog.Errorf("unable to create certificate: %v", err)
		return []string{}, err
	}
	certChain = append(certChain, cresp.GetPemCertificate())
	certChain = append(certChain, cresp.GetPemCertificateChain()...)
	return certChain, nil
}

// GetRootCertBundle:  Get CA certs of the pool from Google CAS API endpoint
func (r *GoogleCASClient) GetRootCertBundle() ([]string, error) {
	var rootCertMap map[string]struct{} = make(map[string]struct{})
	var trustbundle []string = []string{}
	var err error

	ctx := context.Background()

	req := &privatecapb.FetchCaCertsRequest{
		CaPool: r.caSigner,
	}
	resp, err := r.caClient.FetchCaCerts(ctx, req)
	if err != nil {
		googleCAClientLog.Errorf("error when getting root-certs from CAS pool: %v", err)
		return trustbundle, err
	}
	for _, certChain := range resp.CaCerts {
		certs := certChain.Certificates
		rootCert := certs[len(certs)-1]
		if _, ok := rootCertMap[rootCert]; !ok {
			rootCertMap[rootCert] = struct{}{}
		}
	}

	for rootCert := range rootCertMap {
		trustbundle = append(trustbundle, rootCert)
	}
	return trustbundle, nil
}

func (r *GoogleCASClient) Close() {
	r.caClient.Close()
}
