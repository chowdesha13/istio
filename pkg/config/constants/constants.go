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

package constants

const (
	// UnspecifiedIP constant for empty IP address
	UnspecifiedIP = "0.0.0.0"
	// UnspecifiedIPv6 constant for empty IPv6 address
	UnspecifiedIPv6 = "::"

	// AuthCertsPath is the path location for mTLS certificates
	AuthCertsPath = "/etc/certs/"

	// PilotWellKnownDNSCertPath is the path location for Pilot dns serving cert, often used with custom CA integrations
	PilotWellKnownDNSCertPath   = "./var/run/secrets/istiod/tls/"
	PilotWellKnownDNSCaCertPath = "./var/run/secrets/istiod/ca/"

	DefaultPilotTLSCert                = PilotWellKnownDNSCertPath + "tls.crt"
	DefaultPilotTLSKey                 = PilotWellKnownDNSCertPath + "tls.key"
	DefaultPilotTLSCaCert              = PilotWellKnownDNSCaCertPath + "root-cert.pem"
	DefaultPilotTLSCaCertAlternatePath = PilotWellKnownDNSCertPath + "ca.crt"

	// CertChainFilename is mTLS chain file
	CertChainFilename = "cert-chain.pem"

	// DefaultServerCertChain is the default path to the mTLS chain file
	DefaultCertChain = AuthCertsPath + CertChainFilename

	// KeyFilename is mTLS private key
	KeyFilename = "key.pem"

	// DefaultServerKey is the default path to the mTLS private key file
	DefaultKey = AuthCertsPath + KeyFilename

	// RootCertFilename is mTLS root cert
	RootCertFilename = "root-cert.pem"

	// DefaultRootCert is the default path to the mTLS root cert file
	DefaultRootCert = AuthCertsPath + RootCertFilename

	// ConfigPathDir config directory for storing envoy json config files.
	ConfigPathDir = "./etc/istio/proxy"

	// IstioDataDir is the directory to store binary data such as envoy core dump, profile, and downloaded Wasm modules.
	IstioDataDir = "/var/lib/istio/data"

	// BinaryPathFilename envoy binary location
	BinaryPathFilename = "/usr/local/bin/envoy"

	// ServiceClusterName service cluster name used in xDS calls
	ServiceClusterName = "istio-proxy"

	// IstioIngressGatewayName is the internal gateway name assigned to ingress
	IstioIngressGatewayName = "istio-autogenerated-k8s-ingress"

	KubernetesGatewayName = "istio-autogenerated-k8s-gateway"

	// IstioIngressNamespace is the namespace where Istio ingress controller is deployed
	IstioIngressNamespace = "istio-system"

	// DefaultClusterLocalDomain the default service domain suffix for Kubernetes, if not overridden in config.
	DefaultClusterLocalDomain = "cluster.local"

	// DefaultClusterSetLocalDomain is the default domain suffix for Kubernetes Multi-Cluster Services (MCS)
	// used for load balancing requests against endpoints across the ClusterSet (i.e. mesh).
	DefaultClusterSetLocalDomain = "clusterset.local"

	// DefaultClusterName is the default cluster name
	DefaultClusterName = "Kubernetes"

	// IstioLabel indicates that a workload is part of a named Istio system component.
	IstioLabel = "istio"

	// IstioIngressLabelValue is value for IstioLabel that identifies an ingress workload.
	// TODO we should derive this from IngressClass
	IstioIngressLabelValue = "ingressgateway"

	// IstioSystemNamespace is the namespace where Istio's components are deployed
	IstioSystemNamespace = "istio-system"

	// DefaultAuthenticationPolicyName is the name of the cluster-scoped authentication policy. Only
	// policy with this name in the cluster-scoped will be considered.
	DefaultAuthenticationPolicyName = "default"

	// IstioMeshGateway is the built in gateway for all sidecars
	IstioMeshGateway = "mesh"

	// The data name in the ConfigMap of each namespace storing the root cert of non-Kube CA.
	CACertNamespaceConfigMapDataName = "root-cert.pem"

	// PodInfoLabelsPath is the filepath that pod labels will be stored
	// This is typically set by the downward API
	PodInfoLabelsPath = "./etc/istio/pod/labels"

	// PodInfoAnnotationsPath is the filepath that pod annotations will be stored
	// This is typically set by the downward API
	PodInfoAnnotationsPath = "./etc/istio/pod/annotations"

	// DefaultServiceAccountName is the default service account to use for remote cluster access.
	DefaultServiceAccountName = "istio-reader-service-account"

	// DefaultConfigServiceAccountName is the default service account to use for external Istiod config cluster access.
	DefaultConfigServiceAccountName = "istiod"

	// KubeSystemNamespace is the system namespace where we place kubernetes system components.
	KubeSystemNamespace string = "kube-system"

	// KubePublicNamespace is the namespace where we place kubernetes public info (ConfigMaps).
	KubePublicNamespace string = "kube-public"

	// KubeNodeLeaseNamespace is the namespace for the lease objects associated with each kubernetes node.
	KubeNodeLeaseNamespace string = "kube-node-lease"

	// LocalPathStorageNamespace is the namespace for dynamically provisioning persistent local storage with
	// Kubernetes. Typically used with the Kind cluster: https://github.com/rancher/local-path-provisioner
	LocalPathStorageNamespace string = "local-path-storage"

	TestVMLabel = "istio.io/test-vm"

	TestVMVersionLabel = "istio.io/test-vm-version"

	// Label to skip config comparison.
	AlwaysPushLabel = "internal.istio.io/always-push"

	// InternalParentNames declares the original resources of an internally-generated config.
	// This is used by k8s gateway-api.
	// It is a comma separated list. For example, "HTTPRoute/foo.default,HTTPRoute/bar.default"
	InternalParentNames      = "internal.istio.io/parents"
	InternalRouteSemantics   = "internal.istio.io/route-semantics"
	RouteSemanticsIngress    = "ingress"
	RouteSemanticsGateway    = "gateway"
	InternalGatewaySemantics = "internal.istio.io/gateway-semantics"
	GatewaySemanticsGateway  = "gateway"

	// ThirdPartyJwtPath is the default 3P token to authenticate with third party services
	ThirdPartyJwtPath = "./var/run/secrets/tokens/istio-token"

	// CertProviderIstiod uses istiod self signed DNS certificates for the control plane
	CertProviderIstiod = "istiod"
	// CertProviderKubernetes uses the Kubernetes CSR API to generate a DNS certificate for the control plane
	CertProviderKubernetes = "kubernetes"
	// CertProviderKubernetesSignerPrefix uses the Kubernetes CSR API and the specified signer to generate a DNS certificate for the control plane
	CertProviderKubernetesSignerPrefix = "k8s.io/"
	// CertProviderCustom uses the custom root certificate mounted in a well known location for the control plane
	CertProviderCustom = "custom"
	// CertProviderNone does not create any certificates for the control plane. It is assumed that some external
	// load balancer, such as an Istio Gateway, is terminating the TLS.
	CertProviderNone = "none"

	// AlwaysReject is a special internal annotation that is always rejected in the validation webhook. This is used for
	// testing the validation webhook.
	AlwaysReject = "internal.istio.io/webhook-always-reject"

	WaypointServiceAccount = "istio.io/for-service-account"
	WaypointForAddressType = "istio.io/waypoint-for"

	ManagedGatewayLabel               = "gateway.istio.io/managed"
	UnmanagedGatewayController        = "istio.io/unmanaged-gateway"
	ManagedGatewayControllerLabel     = "istio.io-gateway-controller"
	ManagedGatewayMeshControllerLabel = "istio.io-mesh-controller"
	ManagedGatewayMeshController      = "istio.io/mesh-controller"

	RemoteGatewayClassName   = "istio-remote"
	WaypointGatewayClassName = "istio-waypoint"

	// DeprecatedGatewayNameLabel indicates the gateway managing a particular proxy instances. Only populated for Gateway API gateways
	DeprecatedGatewayNameLabel = "istio.io/gateway-name"
	// GatewayNameLabel indicates the gateway managing a particular proxy instances. Only populated for Gateway API gateways
	GatewayNameLabel = "gateway.networking.k8s.io/gateway-name"

	// TODO formalize this API
	// TODO additional values to represent passthrough and hbone or both
	ListenerModeOption          = "gateway.istio.io/listener-protocol"
	ListenerModeAutoPassthrough = "auto-passthrough"

	// DataplaneMode namespace label for determining ambient mesh behavior
	DataplaneMode        = "istio.io/dataplane-mode"
	DataplaneModeAmbient = "ambient"

	// AmbientRedirection specifies whether a pod has ambient redirection (to ztunnel) configured.
	AmbientRedirection = "ambient.istio.io/redirection"
	// AmbientRedirectionEnabled indicates redirection is configured. This is set by the CNI when it
	// actually sets up redirection, rather than by the user.
	AmbientRedirectionEnabled = "enabled"
	// AmbientRedirectionDisabled is an opt-out, configured by user.
	AmbientRedirectionDisabled = "disabled"

	// AmbientUseWaypoint is the annotation used to specify which waypoint should be used for a given pod, service, etc...
	AmbientUseWaypoint = "istio.io/use-waypoint"

	// ServiceTraffic indicates that service traffic should go through the intended waypoint.
	ServiceTraffic = "service"
	// WorkloadTraffic indicates that workload traffic should go through the intended waypoint.
	WorkloadTraffic = "workload"
	// AllTraffic indicates that all traffic should go through the intended waypoint.
	AllTraffic = "all"
	// NoTraffic indicates that no traffic should go through the intended waypoint.
	NoTraffic = "none"
)
