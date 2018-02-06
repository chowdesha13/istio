// Copyright 2017 Istio Authors
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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"k8s.io/client-go/kubernetes"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"istio.io/istio/pkg/collateral"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/probe"
	"istio.io/istio/pkg/version"
	grpcclient "istio.io/istio/security/pkg/caclient/grpc"
	"istio.io/istio/security/pkg/cmd"
	"istio.io/istio/security/pkg/pki/ca"
	"istio.io/istio/security/pkg/pki/ca/controller"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/istio/security/pkg/platform"
	"istio.io/istio/security/pkg/registry"
	"istio.io/istio/security/pkg/registry/kube"
	"istio.io/istio/security/pkg/server/grpc"
	pb "istio.io/istio/security/proto"
)

const (
	defaultCACertTTL = 365 * 24 * time.Hour

	defaultWorkloadCertTTL = time.Hour

	maxWorkloadCertTTL = 7 * 24 * time.Hour

	defaultProbeCheckInterval = 30 * time.Second

	// The default issuer organization for self-signed CA certificate.
	selfSignedCAOrgDefault = "k8s.cluster.local"

	// The default identity for the liveness probe check
	livenessProbeClientIdentity = "k8s.cluster.local"

	// The key for the environment variable that specifies the namespace.
	namespaceKey = "NAMESPACE"
)

type cliOptions struct {
	certChainFile   string
	signingCertFile string
	signingKeyFile  string
	rootCertFile    string

	namespace string

	istioCaStorageNamespace string

	kubeConfigFile string

	selfSignedCA    bool
	selfSignedCAOrg string

	caCertTTL          time.Duration
	workloadCertTTL    time.Duration
	maxWorkloadCertTTL time.Duration

	grpcHostname string
	grpcPort     int

	loggingOptions *log.Options

	// The path to the file which indicates the liveness of the server by its existence.
	// This will be used for k8s liveness probe. If empty, it does nothing.
	LivenessProbeOptions *probe.Options

	probeCheckInterval time.Duration
}

var (
	opts = cliOptions{
		loggingOptions:       log.NewOptions(),
		LivenessProbeOptions: &probe.Options{},
	}

	rootCmd = &cobra.Command{
		Use:   "istio_ca",
		Short: "Istio Certificate Authority (CA)",
		Run: func(cmd *cobra.Command, args []string) {
			runCA()
		},
	}
)

// LivenessCheckController updates the availability of the liveness probe of the CA instance
type LivenessCheckController struct {
	rootCertFile       string
	interval           time.Duration
	grpcHostname       string
	grpcPort           int
	serviceIdentityOrg string
	rsaKeySize         int
	ca                 *ca.IstioCA
	caCertTTL          time.Duration
	livenessProbe      *probe.Probe
	client             *grpcclient.CAGrpcClientImpl
}

func (c *LivenessCheckController) checkGrpcServer() error {
	if c.grpcPort <= 0 {
		return nil
	}

	// generates certificate and private key for test
	opts := util.CertOptions{
		Host:       livenessProbeClientIdentity,
		RSAKeySize: 2048,
	}

	csrPEM, privPEM, err := util.GenCSR(opts)
	if err != nil {
		log.Error(err.Error())
	}

	certPEM, err := c.ca.Sign(csrPEM, c.interval, false)
	if err != nil {
		log.Error(err.Error())
	}

	testCert, err := ioutil.TempFile("/tmp", "cert")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(testCert.Name())
	}()

	testKey, err := ioutil.TempFile("/tmp", "priv")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.Remove(testKey.Name())
	}()

	err = ioutil.WriteFile(testCert.Name(), certPEM, 0644)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(testKey.Name(), privPEM, 0644)
	if err != nil {
		return err
	}

	pc := platform.NewOnPremClientImpl(platform.OnPremConfig{
		RootCACertFile: c.rootCertFile,
		KeyFile:        testKey.Name(),
		CertChainFile:  testCert.Name(),
	})

	csr, _, err := util.GenCSR(util.CertOptions{
		Host:       livenessProbeClientIdentity,
		Org:        c.serviceIdentityOrg,
		RSAKeySize: c.rsaKeySize,
	})

	if err != nil {
		return err
	}

	cred, err := pc.GetAgentCredential()
	if err != nil {
		return err
	}

	req := &pb.CsrRequest{
		CsrPem:              csr,
		NodeAgentCredential: cred,
		CredentialType:      pc.GetCredentialType(),
		RequestedTtlMinutes: 60,
	}

	_, err = c.client.SendCSR(req, pc, fmt.Sprintf("%v:%v", c.grpcHostname, c.grpcPort))

	return err
}

// Run starts the check routine
func (c *LivenessCheckController) Run() {
	go func() {
		t := time.NewTicker(c.interval)
		for {
			select {
			case <-t.C:
				c.livenessProbe.SetAvailable(c.checkGrpcServer())
			}
		}
	}()
}

func fatalf(template string, args ...interface{}) {
	if len(args) > 0 {
		log.Errorf(template, args)
	} else {
		log.Errorf(template)
	}
	os.Exit(-1)
}

func init() {
	flags := rootCmd.Flags()

	flags.StringVar(&opts.certChainFile, "cert-chain", "", "Speicifies path to the certificate chain file")
	flags.StringVar(&opts.signingCertFile, "signing-cert", "", "Specifies path to the CA signing certificate file")
	flags.StringVar(&opts.signingKeyFile, "signing-key", "", "Specifies path to the CA signing key file")
	flags.StringVar(&opts.rootCertFile, "root-cert", "", "Specifies path to the root certificate file")

	flags.StringVar(&opts.namespace, "namespace", "",
		"Select a namespace for the CA to listen to. If unspecified, Istio CA tries to use the ${"+namespaceKey+"} "+
			"environment variable. If neither is set, Istio CA listens to all namespaces.")
	flags.StringVar(&opts.istioCaStorageNamespace, "istio-ca-storage-namespace", "istio-system", "Namespace where "+
		"the Istio CA pods is running. Will not be used if explicit file or other storage mechanism is specified.")

	flags.StringVar(&opts.kubeConfigFile, "kube-config", "",
		"Specifies path to kubeconfig file. This must be specified when not running inside a Kubernetes pod.")

	flags.BoolVar(&opts.selfSignedCA, "self-signed-ca", false,
		"Indicates whether to use auto-generated self-signed CA certificate. "+
			"When set to true, the '--signing-cert' and '--signing-key' options are ignored.")
	flags.StringVar(&opts.selfSignedCAOrg, "self-signed-ca-org", "k8s.cluster.local",
		fmt.Sprintf("The issuer organization used in self-signed CA certificate (default to %s)",
			selfSignedCAOrgDefault))

	flags.DurationVar(&opts.caCertTTL, "ca-cert-ttl", defaultCACertTTL,
		"The TTL of self-signed CA root certificate")
	flags.DurationVar(&opts.workloadCertTTL, "workload-cert-ttl", defaultWorkloadCertTTL, "The TTL of issued workload certificates")
	flags.DurationVar(&opts.maxWorkloadCertTTL, "max-workload-cert-ttl", maxWorkloadCertTTL, "The max TTL of issued workload certificates")

	flags.StringVar(&opts.grpcHostname, "grpc-hostname", "localhost", "Specifies the hostname for GRPC server.")
	flags.IntVar(&opts.grpcPort, "grpc-port", 0, "Specifies the port number for GRPC server. "+
		"If unspecified, Istio CA will not server GRPC request.")

	flags.StringVar(&opts.LivenessProbeOptions.Path, "livenessProbePath", "",
		"Path to the file for the liveness probe.")
	flags.DurationVar(&opts.LivenessProbeOptions.UpdateInterval, "livenessProbeInterval", 0,
		"Interval of updating file for the liveness probe.")

	flags.DurationVar(&opts.probeCheckInterval, "probeCheckInterval", defaultProbeCheckInterval,
		"Interval of checking the liveness of the CA.")

	rootCmd.AddCommand(version.CobraCommand())

	rootCmd.AddCommand(collateral.CobraCommand(rootCmd, &doc.GenManHeader{
		Title:   "Istio CA",
		Section: "istio_ca CLI",
		Manual:  "Istio CA",
	}))

	opts.loggingOptions.AttachCobraFlags(rootCmd)
	cmd.InitializeFlags(rootCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errora(err)
		os.Exit(-1)
	}
}

func runCA() {
	if err := log.Configure(opts.loggingOptions); err != nil {
		fatalf("Failed to configure logging (%v)", err)
	}

	if value, exists := os.LookupEnv(namespaceKey); exists {
		// When -namespace is not set, try to read the namespace from environment variable.
		if opts.namespace == "" {
			opts.namespace = value
		}
		// Use environment variable for istioCaStorageNamespace if it exists
		opts.istioCaStorageNamespace = value
	}

	verifyCommandLineOptions()

	cs := createClientset()
	ca := createCA(cs.CoreV1())
	// For workloads in K8s, we apply the configured workload cert TTL.
	sc := controller.NewSecretController(ca, opts.workloadCertTTL, cs.CoreV1(), opts.namespace)

	stopCh := make(chan struct{})
	sc.Run(stopCh)

	if opts.grpcPort > 0 {
		// start registry if gRPC server is to be started
		reg := registry.GetIdentityRegistry()

		// add certificate identity to the identity registry for the liveness probe check
		if err := reg.AddMapping(livenessProbeClientIdentity, livenessProbeClientIdentity); err != nil {
			log.Errorf("failed to add indentity mapping: %v", err)
		}

		ch := make(chan struct{})

		// monitor service objects with "alpha.istio.io/kubernetes-serviceaccounts" annotation
		serviceController := kube.NewServiceController(cs.CoreV1(), opts.namespace, reg)
		serviceController.Run(ch)

		// monitor service account objects for istio mesh expansion
		serviceAccountController := kube.NewServiceAccountController(cs.CoreV1(), opts.namespace, reg)
		serviceAccountController.Run(ch)

		// The CA API uses cert with the max workload cert TTL.
		grpcServer := grpc.New(ca, opts.maxWorkloadCertTTL, opts.grpcHostname, opts.grpcPort)
		if err := grpcServer.Run(); err != nil {
			// stop the registry-related controllers
			ch <- struct{}{}

			log.Warnf("Failed to start GRPC server with error: %v", err)
		}
	}

	log.Info("Istio CA has started")
	select {} // wait forever
}

func createClientset() *kubernetes.Clientset {
	c := generateConfig()
	cs, err := kubernetes.NewForConfig(c)
	if err != nil {
		fatalf("Failed to create a clientset (error: %s)", err)
	}
	return cs
}

func createCA(core corev1.SecretsGetter) ca.CertificateAuthority {
	var caOpts *ca.IstioCAOptions
	var err error

	if opts.selfSignedCA {
		log.Info("Use self-signed certificate as the CA certificate")

		// TODO(wattli): Refactor this and combine it with NewIstioCA().
		caOpts, err = ca.NewSelfSignedIstioCAOptions(opts.caCertTTL, opts.workloadCertTTL,
			opts.maxWorkloadCertTTL, opts.selfSignedCAOrg, opts.istioCaStorageNamespace, core)
		if err != nil {
			fatalf("Failed to create a self-signed Istio CA (error: %v)", err)
		}
	} else {
		var certChainBytes []byte
		if opts.certChainFile != "" {
			certChainBytes = readFile(opts.certChainFile)
		}
		caOpts = &ca.IstioCAOptions{
			CertChainBytes:   certChainBytes,
			CertTTL:          opts.workloadCertTTL,
			MaxCertTTL:       opts.maxWorkloadCertTTL,
			SigningCertBytes: readFile(opts.signingCertFile),
			SigningKeyBytes:  readFile(opts.signingKeyFile),
			RootCertBytes:    readFile(opts.rootCertFile),
		}
	}

	caOpts.LivenessProbeOptions = opts.LivenessProbeOptions
	caOpts.ProbeCheckInterval = opts.probeCheckInterval

	istioCA, err := ca.NewIstioCA(caOpts)
	if err != nil {
		log.Errorf("Failed to create an Istio CA (error: %v)", err)
	}

	if opts.LivenessProbeOptions.IsValid() {
		livenessProbe := probe.NewProbe()
		livenessProbeController := probe.NewFileController(opts.LivenessProbeOptions)
		livenessProbe.RegisterProbe(livenessProbeController, "liveness")
		livenessProbeController.Start()

		// set initial status to good
		livenessProbe.SetAvailable(nil)

		livenessProbeChecker := &LivenessCheckController{
			rootCertFile: opts.rootCertFile,
			interval:     opts.probeCheckInterval,
			grpcHostname: opts.grpcHostname,
			grpcPort:     opts.grpcPort,
			rsaKeySize:   2048,

			livenessProbe: livenessProbe,

			ca:        istioCA,
			caCertTTL: opts.caCertTTL,
			client:    &grpcclient.CAGrpcClientImpl{},
		}
		livenessProbeChecker.Run()
	}

	return istioCA
}

func generateConfig() *rest.Config {
	if opts.kubeConfigFile != "" {
		c, err := clientcmd.BuildConfigFromFlags("", opts.kubeConfigFile)
		if err != nil {
			fatalf("Failed to create a config object from file %s, (error %v)", opts.kubeConfigFile, err)
		}
		return c
	}

	// When `kubeConfigFile` is unspecified, use the in-cluster configuration.
	c, err := rest.InClusterConfig()
	if err != nil {
		fatalf("Failed to create a in-cluster config (error: %s)", err)
	}
	return c
}

func readFile(filename string) []byte {
	bs, err := ioutil.ReadFile(filename)
	if err != nil {
		fatalf("Failed to read file %s (error: %v)", filename, err)
	}
	return bs
}

func verifyCommandLineOptions() {
	if opts.selfSignedCA {
		return
	}

	if opts.signingCertFile == "" {
		fatalf(
			"No signing cert has been specified. Either specify a cert file via '-signing-cert' option " +
				"or use '-self-signed-ca'")
	}

	if opts.signingKeyFile == "" {
		fatalf(
			"No signing key has been specified. Either specify a key file via '-signing-key' option " +
				"or use '-self-signed-ca'")
	}

	if opts.rootCertFile == "" {
		fatalf(
			"No root cert has been specified. Either specify a root cert file via '-root-cert' option " +
				"or use '-self-signed-ca'")
	}
}
