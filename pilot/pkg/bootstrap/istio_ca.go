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

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/api/security/v1beta1"
	"istio.io/istio/pilot/pkg/features"
	securityModel "istio.io/istio/pilot/pkg/security/model"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/jwt"
	"istio.io/istio/pkg/kube/namespace"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/cmd"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/pki/ra"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	caserver "istio.io/istio/security/pkg/server/ca"
	"istio.io/istio/security/pkg/server/ca/authenticate"
	"istio.io/istio/security/pkg/util"
)

type caOptions struct {
	// Either extCAK8s or extCAGrpc
	ExternalCAType   ra.CaExternalType
	ExternalCASigner string
	// domain to use in SPIFFE identity URLs
	TrustDomain      string
	Namespace        string
	Authenticators   []security.Authenticator
	CertSignerDomain string
	DiscoveryFilter  namespace.DiscoveryFilter
}

// Based on istio_ca main - removing creation of Secrets with private keys in all namespaces and install complexity.
//
// For backward compat, will preserve support for the "cacerts" Secret used for self-signed certificates.
// It is mounted in the same location, and if found will be used - creating the secret is sufficient, no need for
// extra options.
//
// In old installer, the LocalCertDir is hardcoded to /etc/cacerts and mounted from "cacerts" secret.
//
// Support for signing other root CA has been removed - too dangerous, no clear use case.
//
// Default config, for backward compat with Citadel:
// - if "cacerts" secret exists in istio-system, will be mounted. It may contain an optional "root-cert.pem",
// with additional roots and optional {ca-key, ca-cert, cert-chain}.pem user-provided root CA.
// - if user-provided root CA is not found, the Secret "istio-ca-secret" is used, with ca-cert.pem and ca-key.pem files.
// - if neither is found, istio-ca-secret will be created.
//
// - a config map "istio-security" with a "caTLSRootCert" file will be used for root cert, and created if needed.
//   The config map was used by node agent - no longer possible to use in sds-agent, but we still save it for
//   backward compat. Will be removed with the node-agent. sds-agent is calling NewCitadelClient directly, using
//   K8S root.

var (
	// LocalCertDir replaces the "cert-chain", "signing-cert" and "signing-key" flags in citadel - Istio installer is
	// requires a secret named "cacerts" with specific files inside.
	LocalCertDir = env.Register("ROOT_CA_DIR", "./etc/cacerts",
		"Location of a local or mounted CA root")

	useRemoteCerts = env.Register("USE_REMOTE_CERTS", false,
		"Whether to try to load CA certs from config Kubernetes cluster. Used for external Istiod.")

	workloadCertTTL = env.Register("DEFAULT_WORKLOAD_CERT_TTL",
		cmd.DefaultWorkloadCertTTL,
		"The default TTL of issued workload certificates. Applied when the client sets a "+
			"non-positive TTL in the CSR.")

	maxWorkloadCertTTL = env.Register("MAX_WORKLOAD_CERT_TTL",
		cmd.DefaultMaxWorkloadCertTTL,
		"The max TTL of issued workload certificates.")

	SelfSignedCACertTTL = env.Register("CITADEL_SELF_SIGNED_CA_CERT_TTL",
		cmd.DefaultSelfSignedCACertTTL,
		"The TTL of self-signed CA root certificate.")

	selfSignedRootCertCheckInterval = env.Register("CITADEL_SELF_SIGNED_ROOT_CERT_CHECK_INTERVAL",
		cmd.DefaultSelfSignedRootCertCheckInterval,
		"The interval that self-signed CA checks its root certificate "+
			"expiration time and rotates root certificate. Setting this interval "+
			"to zero or a negative value disables automated root cert check and "+
			"rotation. This interval is suggested to be larger than 10 minutes.")

	selfSignedRootCertGracePeriodPercentile = env.Register("CITADEL_SELF_SIGNED_ROOT_CERT_GRACE_PERIOD_PERCENTILE",
		cmd.DefaultRootCertGracePeriodPercentile,
		"Grace period percentile for self-signed root cert.")

	enableJitterForRootCertRotator = env.Register("CITADEL_ENABLE_JITTER_FOR_ROOT_CERT_ROTATOR",
		true,
		"If true, set up a jitter to start root cert rotator. "+
			"Jitter selects a backoff time in seconds to start root cert rotator, "+
			"and the back off time is below root cert check interval.")

	k8sInCluster = env.Register("KUBERNETES_SERVICE_HOST", "",
		"Kubernetes service host, set automatically when running in-cluster")

	// This value can also be extracted from the mounted token
	trustedIssuer = env.Register("TOKEN_ISSUER", "",
		"OIDC token issuer. If set, will be used to check the tokens.")

	audience = env.Register("AUDIENCE", "",
		"Expected audience in the tokens. ")

	caRSAKeySize = env.Register("CITADEL_SELF_SIGNED_CA_RSA_KEY_SIZE", 2048,
		"Specify the RSA key size to use for self-signed Istio CA certificates.")

	// TODO: Likely to be removed and added to mesh config
	externalCaType = env.Register("EXTERNAL_CA", "",
		"External CA Integration Type. Permitted Values are ISTIOD_RA_KUBERNETES_API or "+
			"ISTIOD_RA_ISTIO_API").Get()

	// TODO: Likely to be removed and added to mesh config
	k8sSigner = env.Register("K8S_SIGNER", "",
		"Kubernates CA Signer type. Valid from Kubernates 1.18").Get()
)

// RunCA will start the cert signing GRPC service on an existing server.
// Protected by installer options: the CA will be started only if the JWT token in /var/run/secrets
// is mounted. If it is missing - for example old versions of K8S that don't support such tokens -
// we will not start the cert-signing server, since pods will have no way to authenticate.
func (s *Server) RunCA(grpc *grpc.Server, ca caserver.CertificateAuthority, opts *caOptions) {
	iss := trustedIssuer.Get()
	aud := audience.Get()

	token, err := os.ReadFile(getJwtPath())
	if err == nil {
		tok, err := detectAuthEnv(string(token))
		if err != nil {
			log.Warnf("Starting with invalid K8S JWT token: %v", err)
		} else {
			if iss == "" {
				iss = tok.Iss
			}
			if len(tok.Aud) > 0 && len(aud) == 0 {
				aud = tok.Aud[0]
			}
		}
	}

	// The CA API uses cert with the max workload cert TTL.
	// 'hostlist' must be non-empty - but is not used since a grpc server is passed.
	// Adds client cert auth and kube (sds enabled)
	caServer, startErr := caserver.New(ca, maxWorkloadCertTTL.Get(), opts.Authenticators, s.kubeClient, opts.DiscoveryFilter)
	if startErr != nil {
		log.Fatalf("failed to create istio ca server: %v", startErr)
	}

	// TODO: if not set, parse Istiod's own token (if present) and get the issuer. The same issuer is used
	// for all tokens - no need to configure twice. The token may also include cluster info to auto-configure
	// networking properties.
	if iss != "" && // issuer set explicitly or extracted from our own JWT
		k8sInCluster.Get() == "" { // not running in cluster - in cluster use direct call to apiserver
		// Add a custom authenticator using standard JWT validation, if not running in K8S
		// When running inside K8S - we can use the built-in validator, which also check pod removal (invalidation).
		jwtRule := v1beta1.JWTRule{Issuer: iss, Audiences: []string{aud}}
		oidcAuth, err := authenticate.NewJwtAuthenticator(&jwtRule)
		if err == nil {
			caServer.Authenticators = append(caServer.Authenticators, oidcAuth)
			log.Info("Using out-of-cluster JWT authentication")
		} else {
			log.Info("K8S token doesn't support OIDC, using only in-cluster auth")
		}
	}

	caServer.Register(grpc)

	log.Info("Istiod CA has started")
}

// detectAuthEnv will use the JWT token that is mounted in istiod to set the default audience
// and trust domain for Istiod, if not explicitly defined.
// K8S will use the same kind of tokens for the pods, and the value in istiod's own token is
// simplest and safest way to have things match.
//
// Note that K8S is not required to use JWT tokens - we will fallback to the defaults
// or require explicit user option for K8S clusters using opaque tokens.
func detectAuthEnv(jwt string) (*authenticate.JwtPayload, error) {
	jwtSplit := strings.Split(jwt, ".")
	if len(jwtSplit) != 3 {
		return nil, fmt.Errorf("invalid JWT parts: %s", jwt)
	}
	payload := jwtSplit[1]

	payloadBytes, err := util.DecodeJwtPart(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode jwt: %v", err.Error())
	}

	structuredPayload := &authenticate.JwtPayload{}
	err = json.Unmarshal(payloadBytes, &structuredPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal jwt: %v", err.Error())
	}

	return structuredPayload, nil
}

// detectSigningCABundle determines in which format the signing ca files are created.
// kubernetes tls secrets mount files as tls.crt,tls.key,ca.crt
// istiod secret is ca-cert.pem ca-key.pem cert-chain.pem root-cert.pem
func detectSigningCABundle() (ca.SigningCAFileBundle, error) {
	tlsSigningFile := path.Join(LocalCertDir.Get(), ca.TLSSecretCACertFile)

	// looking for tls file format (tls.crt)
	if _, err := os.Stat(tlsSigningFile); !os.IsNotExist(err) {
		log.Info("Using kubernetes.io/tls secret type for signing ca files")
		return ca.SigningCAFileBundle{
			RootCertFile: path.Join(LocalCertDir.Get(), ca.TLSSecretRootCertFile),
			CertChainFiles: []string{
				tlsSigningFile,
				path.Join(LocalCertDir.Get(), ca.TLSSecretRootCertFile),
			},
			SigningCertFile: tlsSigningFile,
			SigningKeyFile:  path.Join(LocalCertDir.Get(), ca.TLSSecretCAPrivateKeyFile),
		}, nil
	} else if os.IsNotExist(err) {
		// noop, file does not exist, move on
	} else if err != nil {
		return ca.SigningCAFileBundle{}, err
	}
	log.Info("Using istiod file format for signing ca files")
	// default ca file format
	return ca.SigningCAFileBundle{
		RootCertFile:    path.Join(LocalCertDir.Get(), ca.RootCertFile),
		CertChainFiles:  []string{path.Join(LocalCertDir.Get(), ca.CertChainFile)},
		SigningCertFile: path.Join(LocalCertDir.Get(), ca.CACertFile),
		SigningKeyFile:  path.Join(LocalCertDir.Get(), ca.CAPrivateKeyFile),
	}, nil
}

// loadCACerts loads an existing `cacerts` Secret if the files aren't mounted locally.
// By default, a cacerts Secret would be mounted during pod startup due to the
// Istiod Deployment configuration. But with external Istiod, we want to be
// able to load cacerts from a remote cluster instead.
func (s *Server) loadCACerts(caOpts *caOptions, dir string) error {
	if s.kubeClient == nil {
		return nil
	}

	signingKeyFile := path.Join(dir, ca.CAPrivateKeyFile)
	if _, err := os.Stat(signingKeyFile); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("signing key file %s already exists", signingKeyFile)
	}

	secret, err := s.kubeClient.Kube().CoreV1().Secrets(caOpts.Namespace).Get(
		context.TODO(), ca.ExternalCASecret, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return err
	}

	log.Infof("cacerts Secret found in config cluster, saving contents to %s", dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for key, data := range secret.Data {
		filename := path.Join(dir, key)
		if err := os.WriteFile(filename, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// handleEvent handles the events on cacerts related files.
// If create/write(modified) event occurs, then it verifies that
// newly introduced cacerts are intermediate CA which is generated
// from cuurent root-cert.pem. Then it updates and keycertbundle
// and generates new dns certs.
// TODO(rveerama1): Add support for new ROOT-CA rotation also.
func handleEvent(s *Server) {
	log.Info("Update Istiod cacerts")

	var newCABundle []byte
	var err error

	currentCABundle := s.CA.GetCAKeyCertBundle().GetRootCertPem()

	fileBundle, err := detectSigningCABundle()
	if err != nil {
		log.Errorf("unable to determine signing file format %v", err)
		return
	}
	newCABundle, err = os.ReadFile(fileBundle.RootCertFile)

	if err != nil {
		log.Errorf("failed reading root-cert.pem: %v", err)
		return
	}

	// Only updating intermediate CA is supported now
	if !bytes.Equal(currentCABundle, newCABundle) {
		log.Info("Updating new ROOT-CA not supported")
		return
	}

	err = s.CA.GetCAKeyCertBundle().UpdateVerifiedKeyCertBundleFromFile(
		fileBundle.SigningCertFile,
		fileBundle.SigningKeyFile,
		fileBundle.CertChainFiles,
		fileBundle.RootCertFile)

	if err != nil {
		log.Errorf("Failed to update new Plug-in CA certs: %v", err)
		return
	}

	err = s.updatePluggedinRootCertAndGenKeyCert()
	if err != nil {
		log.Errorf("Failed generating plugged-in istiod key cert: %v", err)
		return
	}

	log.Info("Istiod has detected the newly added intermediate CA and updated its key and certs accordingly")
}

// handleCACertsFileWatch handles the events on cacerts files
func (s *Server) handleCACertsFileWatch() {
	var timerC <-chan time.Time
	for {
		select {
		case <-timerC:
			timerC = nil
			handleEvent(s)

		case event, ok := <-s.cacertsWatcher.Events:
			if !ok {
				log.Debug("plugin cacerts watch stopped")
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if timerC == nil {
					timerC = time.After(100 * time.Millisecond)
				}
			}

		case err := <-s.cacertsWatcher.Errors:
			if err != nil {
				log.Errorf("failed to catch events on cacerts file: %v", err)
				return
			}

		case <-s.internalStop:
			return
		}
	}
}

func (s *Server) addCACertsFileWatcher(dir string) error {
	err := s.cacertsWatcher.Add(dir)
	if err != nil {
		log.Infof("AUTO_RELOAD_PLUGIN_CERTS will not work, failed to add file watcher: %v", err)
		return err
	}

	log.Infof("Added cacerts files watcher at %v", dir)

	return nil
}

// initCACertsWatcher initializes the cacerts (/etc/cacerts) directory.
// In particular it monitors 'ca-key.pem', 'ca-cert.pem', 'root-cert.pem'
// and 'cert-chain.pem'.
func (s *Server) initCACertsWatcher() {
	var err error

	s.cacertsWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		log.Infof("failed to add CAcerts watcher: %v", err)
		return
	}

	err = s.addCACertsFileWatcher(LocalCertDir.Get())
	if err != nil {
		return
	}

	go s.handleCACertsFileWatch()
}

// createIstioCA initializes the Istio CA signing functionality.
// - for 'plugged in', uses ./etc/cacert directory, mounted from 'cacerts' secret in k8s.
//
//	Inside, the key/cert are 'ca-key.pem' and 'ca-cert.pem'. The root cert signing the intermediate is root-cert.pem,
//	which may contain multiple roots. A 'cert-chain.pem' file has the full cert chain.
func (s *Server) createIstioCA(opts *caOptions) (*ca.IstioCA, error) {
	var caOpts *ca.IstioCAOptions
	var err error

	fileBundle, err := detectSigningCABundle()
	if err != nil {
		return nil, fmt.Errorf("unable to determine signing file format %v", err)
	}
	if _, err := os.Stat(fileBundle.RootCertFile); err != nil {
		// In Citadel, normal self-signed doesn't use a root-cert.pem file for additional roots.
		// In Istiod, it is possible to provide one via "cacerts" secret in both cases, for consistency.
		fileBundle.RootCertFile = ""
	}
	if _, err := os.Stat(fileBundle.SigningKeyFile); err != nil {
		// The user-provided certs are missing - create a self-signed cert.
		if s.kubeClient != nil {
			log.Info("Use self-signed certificate as the CA certificate")

			// Abort after 20 minutes.
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
			defer cancel()
			// rootCertFile will be added to "ca-cert.pem".
			// readSigningCertOnly set to false - it doesn't seem to be used in Citadel, nor do we have a way
			// to set it only for one job.
			ssOpts := ca.SelfSignedIstioCAOptions{
				RootCertGracePeriodPercentile: selfSignedRootCertGracePeriodPercentile.Get(),
				CaCertTTL:                     SelfSignedCACertTTL.Get(),
				RootCertCheckInverval:         selfSignedRootCertCheckInterval.Get(),
				DefaultCertTTL:                workloadCertTTL.Get(),
				MaxCertTTL:                    maxWorkloadCertTTL.Get(),
				Org:                           opts.TrustDomain,
				DualUse:                       true,
				Namespace:                     opts.Namespace,
				Client:                        s.kubeClient.Kube().CoreV1(),
				RootCertFile:                  fileBundle.RootCertFile,
				EnableJitter:                  enableJitterForRootCertRotator.Get(),
				CaRSAKeySize:                  caRSAKeySize.Get(),
				AlgorithmType:                 pkiutil.SupportedAlgorithmTypes(features.SelfSignedAlgorithm),
				EcSigAlg:                      features.EccSigAlgEnv,
				EccCurve:                      features.EccCurvEnv,
			}

			caOpts, err = ca.NewSelfSignedIstioCAOptions(ctx, &ssOpts)
		} else {
			log.Warnf(
				"Use local self-signed CA certificate for testing. Will use in-memory root CA, no K8S access and no ca key file %s",
				fileBundle.SigningKeyFile)

			caOpts, err = ca.NewSelfSignedDebugIstioCAOptions(fileBundle.RootCertFile, SelfSignedCACertTTL.Get(),
				workloadCertTTL.Get(), maxWorkloadCertTTL.Get(), opts.TrustDomain, caRSAKeySize.Get(),
				features.SelfSignedAlgorithm, features.EccSigAlgEnv, features.EccCurvEnv)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create a self-signed istiod CA: %v", err)
		}
	} else {
		log.Info("Use local CA certificate")

		caOpts, err = ca.NewPluggedCertIstioCAOptions(fileBundle, workloadCertTTL.Get(), maxWorkloadCertTTL.Get(), caRSAKeySize.Get(),
			features.SelfSignedAlgorithm, features.EccSigAlgEnv, features.EccCurvEnv)
		if err != nil {
			return nil, fmt.Errorf("failed to create an istiod CA: %v", err)
		}

		s.initCACertsWatcher()
	}
	istioCA, err := ca.NewIstioCA(caOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create an istiod CA: %v", err)
	}

	// TODO: provide an endpoint returning all the roots. SDS can only pull a single root in current impl.
	// ca.go saves or uses the secret, but also writes to the configmap "istio-security", under caTLSRootCert
	// rootCertRotatorChan channel accepts signals to stop root cert rotator for
	// self-signed CA.
	// Start root cert rotator in a separate goroutine.
	istioCA.Run(s.internalStop)
	return istioCA, nil
}

// createIstioRA initializes the Istio RA signing functionality.
// the caOptions defines the external provider
// ca cert can come from three sources, order matters:
// 1. Define ca cert via kubernetes secret and mount the secret through `external-ca-cert` volume
// 2. Use kubernetes ca cert `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` if signer is
//
//	kubernetes built-in `kubernetes.io/legacy-unknown" signer
//
// 3. Extract from the cert-chain signed by other CSR signer.
func (s *Server) createIstioRA(opts *caOptions) (ra.RegistrationAuthority, error) {
	caCertFile := path.Join(ra.DefaultExtCACertDir, constants.CACertNamespaceConfigMapDataName)
	certSignerDomain := opts.CertSignerDomain
	_, err := os.Stat(caCertFile)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to get file info: %v", err)
		}

		// File does not exist.
		if certSignerDomain == "" {
			log.Infof("CA cert file %q not found, using %q.", caCertFile, defaultCACertPath)
			caCertFile = defaultCACertPath
		} else {
			log.Infof("CA cert file %q not found - ignoring.", caCertFile)
			caCertFile = ""
		}
	}

	if s.kubeClient == nil {
		return nil, fmt.Errorf("kubeClient is nil")
	}
	raOpts := &ra.IstioRAOptions{
		ExternalCAType:   opts.ExternalCAType,
		DefaultCertTTL:   workloadCertTTL.Get(),
		MaxCertTTL:       maxWorkloadCertTTL.Get(),
		CaSigner:         opts.ExternalCASigner,
		CaCertFile:       caCertFile,
		VerifyAppendCA:   true,
		K8sClient:        s.kubeClient.Kube(),
		TrustDomain:      opts.TrustDomain,
		CertSignerDomain: opts.CertSignerDomain,
	}
	raServer, err := ra.NewIstioRA(raOpts)
	if err != nil {
		return nil, err
	}
	raServer.SetCACertificatesFromMeshConfig(s.environment.Mesh().CaCertificates)
	s.environment.AddMeshHandler(func() {
		meshConfig := s.environment.Mesh()
		caCertificates := meshConfig.CaCertificates
		s.RA.SetCACertificatesFromMeshConfig(caCertificates)
	})
	return raServer, err
}

// getJwtPath returns jwt path.
func getJwtPath() string {
	log.Infof("JWT policy is %v", features.JwtPolicy)
	switch features.JwtPolicy {
	case jwt.PolicyThirdParty:
		return securityModel.K8sSATrustworthyJwtFileName
	case jwt.PolicyFirstParty:
		return securityModel.K8sSAJwtFileName
	default:
		log.Infof("unknown JWT policy %v, default to certificates ", features.JwtPolicy)
		return ""
	}
}
