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

package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"

	"k8s.io/api/admissionregistration/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	caCertServiceAccount          = "default"
	caCertServiceAccountNamespace = "default"
	caKeyInK8sSecret              = "ca.crt"
	certKeyInK8sSecret            = "cert-chain.pem"
)

type enableCliOptions struct {
	// Whether enable the webhook configuration of Galley
	enableValidationWebhook bool
	// The local file path of webhook CA certificate
	caCertPath string
	// The file path of the webhook configuration.
	webhookConfigPath string
	// The name of the ValidatingWebhookConfiguration to manage
	validatingWebhookConfigName string
	// The service name of the validating webhook to manage
	validatingWebhookServiceName string
	// Max time for checking the validating webhook.
	// If the validating webhook is not ready in the given time, exit.
	// Otherwise, apply the webhook configuration.
	maxTimeForCheckingWebhookServer time.Duration
	// Max time for waiting the webhook certificate to be readable.
	maxTimeForReadingWebhookCert time.Duration
	// The name of the secret of the validation webhook.
	// istioctl will check whether the certificate in the secret is issued by
	// the certificate in the k8s service account or the given CA cert, if any.
	validationSecretName string
	// The namespace of the validation secret.
	validationSecretNameSpace string
}

type disableCliOptions struct {
	// Whether disable the webhook configuration of Galley
	disableValidationWebhook bool
	// The name of the ValidatingWebhookConfiguration to manage
	validatingWebhookConfigName string
}

type statusCliOptions struct {
	// Whether display the webhook configuration of Galley
	validationWebhook bool
	// The name of the ValidatingWebhookConfiguration to manage
	validatingWebhookConfigName string
}

// Webhook command to manage webhook configurations
func Webhook() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "webhook",
		Short: "webhook command to manage webhook configurations",
	}

	cmd.AddCommand(newEnableCmd())
	cmd.AddCommand(newDisableCmd())
	cmd.AddCommand(newStatusCmd())

	return cmd
}

func newEnableCmd() *cobra.Command {
	opts := &enableCliOptions{}
	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable webhook configurations",
		Example: `
# Enable the webhook configuration of Galley with the given webhook configuration
istioctl experimental post-install webhook enable --validation --validation-secret istio.webhook.galley 
    --namespace istio-system --config-path validatingwebhookconfiguration.yaml

# Enable the webhook configuration of Galley with the given webhook configuration and CA certificate
istioctl experimental post-install webhook enable --validation --validation-secret istio.webhook.galley 
    --namespace istio-system --config-path validatingwebhookconfiguration.yaml --ca-bundle-file ./k8s-ca-cert.pem
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// --namespace is used as the namespace of the validation secret
			opts.validationSecretNameSpace = namespace
			if len(opts.webhookConfigPath) == 0 {
				return fmt.Errorf("must specify a valid --config-path")
			}
			if len(opts.validationSecretName) == 0 {
				return fmt.Errorf("must specify a valid --validation-secret")
			}
			if !opts.enableValidationWebhook {
				return fmt.Errorf("not enabling validation webhook")
			}
			client, err := createInterface(kubeconfig)
			if err != nil {
				return fmt.Errorf("err when creating k8s client interface: %v", err)
			}
			// Read k8s CA certificate that will be used as the CA bundle of the webhook configuration
			caCert, err := readCACert(client, opts.caCertPath, opts.validationSecretName, opts.validationSecretNameSpace,
				opts.maxTimeForReadingWebhookCert)
			if err != nil {
				return fmt.Errorf("err when reading CA cert: %v", err)
			}
			fmt.Printf("Webhook CA certificate:\n%v\n", string(caCert))
			// Apply the webhook configuration when the Galley webhook server is running.
			err = waitForServerRunning(client, namespace, opts.validatingWebhookServiceName,
				opts.maxTimeForCheckingWebhookServer)
			if err != nil {
				return fmt.Errorf("err when checking webhook server: %v", err)
			}
			webhookConfig, err := buildValidatingWebhookConfig(
				caCert,
				opts.webhookConfigPath,
				opts.validatingWebhookConfigName,
			)
			if err != nil {
				return fmt.Errorf("err when build validatingwebhookconfiguration: %v", err)
			}
			_, err = createValidatingWebhookConfig(client, webhookConfig)
			if err != nil {
				return fmt.Errorf("error when creating validatingwebhookconfiguration: %v", err)
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&opts.enableValidationWebhook, "validation", true, "Specifies whether enabling"+
		"the validating webhook.")
	// Specifies the local file path to webhook CA bundle.
	// If empty, will read CA bundle from default k8s service account.
	flags.StringVar(&opts.caCertPath, "ca-bundle-file", "",
		"Specifies the local file path to the webhook certificate signing CA bundle. "+
			"If the certificate is signed by k8s CA, this parameter needs to "+
			"be consistent with the k8s CA signing certificate, which may be customized through --cluster-signing-cert-file "+
			"(the Kubernetes CA certificate used to sign certificates on kube-controller-manager, details in "+
			"https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/). In the case "+
			"that k8s signing certificate is the same as that of the k8s API server, this parameter may be configured as "+
			"the pod certificate at /var/run/secrets/kubernetes.io/serviceaccount/ca.crt. "+
			"If no local file is specified, the CA certificate will be read from default service account. "+
			"The CA certificate will be verified against the webhook certificate specified in --valiation-secret.")
	flags.StringVar(&opts.webhookConfigPath, "config-path", "",
		"Specifies the file path of the webhook configuration.")
	flags.StringVar(&opts.validatingWebhookConfigName, "config-name", "istio-galley",
		"The name of the ValidatingWebhookConfiguration to manage.")
	flags.StringVar(&opts.validatingWebhookServiceName, "service", "istio-galley",
		"The service name of the validating webhook to manage.")
	flags.StringVar(&opts.validationSecretName, "validation-secret", "",
		"The name of the secret of the validation webhook. istioctl will verify that the webhook certificate "+
			"is issued by the CA certificate.")
	flags.DurationVar(&opts.maxTimeForCheckingWebhookServer, "timeout", 60*time.Second,
		"	Max time for checking the validating webhook server. If the validating webhook server is not ready"+
			"in the given time, exit. Otherwise, apply the webhook configuration.")
	flags.DurationVar(&opts.maxTimeForReadingWebhookCert, "read-cert-timeout", 60*time.Second,
		"	Max time for waiting the webhook certificate to be readable.")

	return cmd
}

func newDisableCmd() *cobra.Command {
	opts := &disableCliOptions{}
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable webhook configurations",
		Example: `
# Disable the webhook configuration of Galley
istioctl experimental post-install webhook disable --validation --config-name istio-galley
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.disableValidationWebhook {
				return fmt.Errorf("not disabling validation webhook")
			}
			client, err := createInterface(kubeconfig)
			if err != nil {
				return fmt.Errorf("err when creating k8s client interface: %v", err)
			}
			err = deleteValidatingWebhookConfig(client, opts.validatingWebhookConfigName)
			if err != nil {
				return fmt.Errorf("error when deleting validatingwebhookconfiguration: %v", err)
			}
			fmt.Printf("validatingwebhookconfiguration %v has been deleted\n", opts.validatingWebhookConfigName)
			return nil
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&opts.disableValidationWebhook, "validation", true, "Specifies whether disabling"+
		"the validating webhook.")
	flags.StringVar(&opts.validatingWebhookConfigName, "config-name", "istio-galley",
		"The name of the ValidatingWebhookConfiguration to disable.")

	return cmd
}

func newStatusCmd() *cobra.Command {
	opts := &statusCliOptions{}
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Get webhook configurations",
		Example: `
# Display the webhook configuration of Galley
istioctl experimental post-install webhook status --validation --config-name istio-galley
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !opts.validationWebhook {
				return fmt.Errorf("not displaying validation webhook status")
			}
			client, err := createInterface(kubeconfig)
			if err != nil {
				return fmt.Errorf("err when creating k8s client interface: %v", err)
			}
			config, err := getValidatingWebhookConfig(client, opts.validatingWebhookConfigName)
			if err != nil {
				return fmt.Errorf("error getting validatingwebhookconfiguration: %v", err)
			}
			b, err := yaml.Marshal(config)
			if err != nil {
				return fmt.Errorf("error when marshaling validatingwebhookconfiguration to yaml: %v", err)
			}
			fmt.Printf("validatingwebhookconfiguration %v is:\n%v\n", opts.validatingWebhookConfigName, string(b))
			return nil
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&opts.validationWebhook, "validation", true, "Specifies whether displaying"+
		"the validating webhook configuration.")
	flags.StringVar(&opts.validatingWebhookConfigName, "config-name", "istio-galley",
		"The name of the ValidatingWebhookConfiguration to display.")

	return cmd
}

// Create the validatingwebhookconfiguration
func createValidatingWebhookConfig(k8sClient kubernetes.Interface,
	config *v1beta1.ValidatingWebhookConfiguration) (*v1beta1.ValidatingWebhookConfiguration, error) {
	var whConfig *v1beta1.ValidatingWebhookConfiguration
	var err error
	client := k8sClient.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations()
	_, err = client.Get(config.Name, metav1.GetOptions{})
	if err == nil {
		fmt.Printf("update webhook configuration %v\n", config.Name)
		whConfig, err = client.Update(config)
	} else {
		fmt.Printf("create webhook configuration %v\n", config.Name)
		whConfig, err = client.Create(config)
	}
	return whConfig, err
}

// Delete the validatingwebhookconfiguration
func deleteValidatingWebhookConfig(k8sClient kubernetes.Interface, name string) error {
	return k8sClient.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Delete(name, &metav1.DeleteOptions{})
}

// Get the validatingwebhookconfiguration
func getValidatingWebhookConfig(k8sClient kubernetes.Interface, name string) (*v1beta1.ValidatingWebhookConfiguration, error) {
	return k8sClient.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Get(name, metav1.GetOptions{})
}

// Read CA certificate and check whether it is a valid certificate.
// First try read CA cert from a local file. If no local file, read from CA cert from default service account.
// Next verify that the webhook certificate is issued by CA cert.
func readCACert(client kubernetes.Interface, certPath, secretName, secretNamespace string, maxWaitTime time.Duration) ([]byte, error) {
	var caCert []byte
	var err error
	if len(certPath) > 0 { // read the CA certificate from a local file
		caCert, err = ioutil.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert, cert. path: %v, error: %v", certPath, err)
		}
	} else {
		// Read the CA certificate from the default service account
		caCert, err = readCACertFromSA(client, caCertServiceAccountNamespace, caCertServiceAccount)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert from %v/%v, error: %v",
				caCertServiceAccountNamespace, caCertServiceAccount, err)
		}
	}
	if err = checkCertificate(caCert); err != nil {
		return nil, fmt.Errorf("ca certificate is invalid: %v", err)
	}

	// Read the webhook certificate and check whether it is issued by CA cert
	startTime := time.Now()
	timerCh := time.After(maxWaitTime - time.Since(startTime))
	var cert []byte
	for {
		cert, err = readCertFromSecret(client, secretName, secretNamespace)
		if err == nil {
			fmt.Printf("finished reading cert %v/%v\n", secretNamespace, secretName)
			break
		}
		fmt.Printf("err reading secret %v/%v: %v\n", secretNamespace, secretName, err)
		select {
		case <-timerCh:
			return nil, fmt.Errorf("the secret %v/%v is not readable within %v", secretNamespace, secretName, maxWaitTime)
		default:
			time.Sleep(2 * time.Second)
		}
	}
	if err = checkCertificate(cert); err != nil {
		return nil, fmt.Errorf("webhook certificate is invalid: %v", err)
	}
	if err = veriyCertChain(cert, caCert); err != nil {
		return nil, fmt.Errorf("k8s CA cert and the webhook cert do not form a valid cert chain. "+
			"if your cluster has a custom k8s signing cert, please specify it in --ca-bundle-file parameter. error: %v", err)
	}

	return caCert, nil
}

func waitForServerRunning(client kubernetes.Interface, namespace, svc string, maxWaitTime time.Duration) error {
	startTime := time.Now()
	timerCh := time.After(maxWaitTime - time.Since(startTime))
	// TODO (lei-tang): the retry here may be implemented through another retry mechanism.
	for {
		// Check the webhook's endpoint to see if it is ready. The webhook's readiness probe reflects the readiness of
		// its https server.
		err := isEndpointReady(client, svc, namespace)
		if err == nil {
			fmt.Printf("the server at %v/%v is running\n", namespace, svc)
			break
		}
		fmt.Printf("the server at %v/%v is not running: %v\n", namespace, svc, err)
		select {
		case <-timerCh:
			return fmt.Errorf("the server at %v/%v is not running within %v", namespace, svc, maxWaitTime)
		default:
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

// Build the desired validatingwebhookconfiguration from the specified CA
// and webhook config file.
func buildValidatingWebhookConfig(
	caCert []byte, webhookConfigPath, webhookConfigName string,
) (*v1beta1.ValidatingWebhookConfiguration, error) {
	// load and validate configuration
	webhookConfigData, err := ioutil.ReadFile(webhookConfigPath)
	if err != nil {
		return nil, err
	}
	var webhookConfig v1beta1.ValidatingWebhookConfiguration
	if err := yaml.Unmarshal(webhookConfigData, &webhookConfig); err != nil {
		return nil, fmt.Errorf("could not decode validatingwebhookconfiguration from %v: %v",
			webhookConfigPath, err)
	}

	// the webhook name is fixed at startup time
	webhookConfig.Name = webhookConfigName

	// patch the ca-cert into the user provided configuration
	for i := range webhookConfig.Webhooks {
		webhookConfig.Webhooks[i].ClientConfig.CABundle = caCert
	}

	return &webhookConfig, nil
}

// Return nil when the endpoint is ready. Otherwise, return an error.
func isEndpointReady(client kubernetes.Interface, svc, namespace string) error {
	ep, err := client.CoreV1().Endpoints(namespace).Get(svc, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if len(ep.Subsets) == 0 {
		return fmt.Errorf("%v/%v endpoint not ready: no subsets", namespace, svc)
	}
	for _, subset := range ep.Subsets {
		if len(subset.Addresses) > 0 {
			return nil
		}
	}
	return fmt.Errorf("%v/%v endpoint not ready: no subset addresses", namespace, svc)
}

// Read secret of a service account.
func readCACertFromSA(client kubernetes.Interface, namespace, svcAcctName string) ([]byte, error) {
	svcAcct, err := client.CoreV1().ServiceAccounts(namespace).Get(svcAcctName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if len(svcAcct.Secrets) == 0 {
		return nil, fmt.Errorf("%v/%v has no secrets", namespace, svcAcctName)
	}
	secretName := svcAcct.Secrets[0].Name
	secret, err := client.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("secret %v/%v is nil", namespace, secretName)
	}
	d, ok := secret.Data[caKeyInK8sSecret]
	if !ok {
		return nil, fmt.Errorf("secret %v/%v does not contain %v", namespace, secretName, caKeyInK8sSecret)
	}
	return d, nil
}

// Read certificate from secret
func readCertFromSecret(client kubernetes.Interface, name, namespace string) ([]byte, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("secret %v/%v is nil", namespace, name)
	}
	d, ok := secret.Data[certKeyInK8sSecret]
	if !ok {
		return nil, fmt.Errorf("secret %v/%v does not contain %v", namespace, name, certKeyInK8sSecret)
	}
	return d, nil
}

// Return nil if certificate is valid. Otherwise, return an error.
func checkCertificate(cert []byte) error {
	b, _ := pem.Decode(cert)
	if b == nil {
		return fmt.Errorf("could not decode pem")
	}
	if b.Type != "CERTIFICATE" {
		return fmt.Errorf("ca certificate contains wrong type: %v", b.Type)
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		return fmt.Errorf("ca certificate parsing returns an error: %v", err)
	}
	return nil
}

// Verify the cert is issued by the CA cert.
// Return nil if the cert is issued by the CA cert. Otherwise, return an error.
func veriyCertChain(cert, caCert []byte) error {
	roots := x509.NewCertPool()
	if roots == nil {
		return fmt.Errorf("failed to create cert pool")
	}
	if ok := roots.AppendCertsFromPEM(caCert); !ok {
		return fmt.Errorf("failed to append CA certificate")
	}
	b, _ := pem.Decode(cert)
	if b == nil {
		return fmt.Errorf("invalid PEM encoded certificate")
	}
	certParsed, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse X.509 certificate")
	}
	_, err = certParsed.Verify(x509.VerifyOptions{
		Roots: roots,
	})
	if err != nil {
		return fmt.Errorf("failed to verify the certificate chain: %v", err)
	}
	return nil
}
