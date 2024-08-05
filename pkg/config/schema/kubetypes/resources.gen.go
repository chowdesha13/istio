// Code generated by pkg/config/schema/codegen/tools/collections.main.go. DO NOT EDIT.

package kubetypes

import (
	k8sioapiadmissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	k8sioapiappsv1 "k8s.io/api/apps/v1"
	k8sioapicertificatesv1 "k8s.io/api/certificates/v1"
	k8sioapicoordinationv1 "k8s.io/api/coordination/v1"
	k8sioapicorev1 "k8s.io/api/core/v1"
	k8sioapidiscoveryv1 "k8s.io/api/discovery/v1"
	k8sioapinetworkingv1 "k8s.io/api/networking/v1"
	k8sioapiextensionsapiserverpkgapisapiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	sigsk8siogatewayapiapisv1 "sigs.k8s.io/gateway-api/apis/v1"
	sigsk8siogatewayapiapisv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	sigsk8siogatewayapiapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	istioioapiextensionsv1alpha1 "istio.io/api/extensions/v1alpha1"
	istioioapimeshv1alpha1 "istio.io/api/mesh/v1alpha1"
	istioioapinetworkingv1alpha3 "istio.io/api/networking/v1alpha3"
	istioioapinetworkingv1beta1 "istio.io/api/networking/v1beta1"
	istioioapisecurityv1beta1 "istio.io/api/security/v1beta1"
	istioioapitelemetryv1alpha1 "istio.io/api/telemetry/v1alpha1"
	apiistioioapiextensionsv1alpha1 "istio.io/client-go/pkg/apis/extensions/v1alpha1"
	apiistioioapinetworkingv1 "istio.io/client-go/pkg/apis/networking/v1"
	apiistioioapinetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	apiistioioapinetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	apiistioioapisecurityv1 "istio.io/client-go/pkg/apis/security/v1"
	apiistioioapitelemetryv1 "istio.io/client-go/pkg/apis/telemetry/v1"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
)

func getGvk(obj any) (config.GroupVersionKind, bool) {
	switch obj.(type) {
	case *istioioapisecurityv1beta1.AuthorizationPolicy:
		return gvk.AuthorizationPolicy, true
	case *apiistioioapisecurityv1.AuthorizationPolicy:
		return gvk.AuthorizationPolicy, true
	case *k8sioapicertificatesv1.CertificateSigningRequest:
		return gvk.CertificateSigningRequest, true
	case *k8sioapicorev1.ConfigMap:
		return gvk.ConfigMap, true
	case *k8sioapiextensionsapiserverpkgapisapiextensionsv1.CustomResourceDefinition:
		return gvk.CustomResourceDefinition, true
	case *k8sioapiappsv1.DaemonSet:
		return gvk.DaemonSet, true
	case *k8sioapiappsv1.Deployment:
		return gvk.Deployment, true
	case *istioioapinetworkingv1alpha3.DestinationRule:
		return gvk.DestinationRule, true
	case *apiistioioapinetworkingv1.DestinationRule:
		return gvk.DestinationRule, true
	case *k8sioapidiscoveryv1.EndpointSlice:
		return gvk.EndpointSlice, true
	case *k8sioapicorev1.Endpoints:
		return gvk.Endpoints, true
	case *istioioapinetworkingv1alpha3.EnvoyFilter:
		return gvk.EnvoyFilter, true
	case *apiistioioapinetworkingv1alpha3.EnvoyFilter:
		return gvk.EnvoyFilter, true
	case *sigsk8siogatewayapiapisv1.GRPCRoute:
		return gvk.GRPCRoute, true
	case *istioioapinetworkingv1alpha3.Gateway:
		return gvk.Gateway, true
	case *apiistioioapinetworkingv1.Gateway:
		return gvk.Gateway, true
	case *sigsk8siogatewayapiapisv1beta1.GatewayClass:
		return gvk.GatewayClass, true
	case *sigsk8siogatewayapiapisv1beta1.HTTPRoute:
		return gvk.HTTPRoute, true
	case *k8sioapinetworkingv1.Ingress:
		return gvk.Ingress, true
	case *k8sioapinetworkingv1.IngressClass:
		return gvk.IngressClass, true
	case *sigsk8siogatewayapiapisv1beta1.Gateway:
		return gvk.KubernetesGateway, true
	case *k8sioapicoordinationv1.Lease:
		return gvk.Lease, true
	case *istioioapimeshv1alpha1.MeshConfig:
		return gvk.MeshConfig, true
	case *istioioapimeshv1alpha1.MeshNetworks:
		return gvk.MeshNetworks, true
	case *k8sioapiadmissionregistrationv1.MutatingWebhookConfiguration:
		return gvk.MutatingWebhookConfiguration, true
	case *k8sioapicorev1.Namespace:
		return gvk.Namespace, true
	case *k8sioapicorev1.Node:
		return gvk.Node, true
	case *istioioapisecurityv1beta1.PeerAuthentication:
		return gvk.PeerAuthentication, true
	case *apiistioioapisecurityv1.PeerAuthentication:
		return gvk.PeerAuthentication, true
	case *k8sioapicorev1.Pod:
		return gvk.Pod, true
	case *istioioapinetworkingv1beta1.ProxyConfig:
		return gvk.ProxyConfig, true
	case *apiistioioapinetworkingv1beta1.ProxyConfig:
		return gvk.ProxyConfig, true
	case *sigsk8siogatewayapiapisv1beta1.ReferenceGrant:
		return gvk.ReferenceGrant, true
	case *istioioapisecurityv1beta1.RequestAuthentication:
		return gvk.RequestAuthentication, true
	case *apiistioioapisecurityv1.RequestAuthentication:
		return gvk.RequestAuthentication, true
	case *k8sioapicorev1.Secret:
		return gvk.Secret, true
	case *k8sioapicorev1.Service:
		return gvk.Service, true
	case *k8sioapicorev1.ServiceAccount:
		return gvk.ServiceAccount, true
	case *istioioapinetworkingv1alpha3.ServiceEntry:
		return gvk.ServiceEntry, true
	case *apiistioioapinetworkingv1.ServiceEntry:
		return gvk.ServiceEntry, true
	case *istioioapinetworkingv1alpha3.Sidecar:
		return gvk.Sidecar, true
	case *apiistioioapinetworkingv1.Sidecar:
		return gvk.Sidecar, true
	case *k8sioapiappsv1.StatefulSet:
		return gvk.StatefulSet, true
	case *sigsk8siogatewayapiapisv1alpha2.TCPRoute:
		return gvk.TCPRoute, true
	case *sigsk8siogatewayapiapisv1alpha2.TLSRoute:
		return gvk.TLSRoute, true
	case *istioioapitelemetryv1alpha1.Telemetry:
		return gvk.Telemetry, true
	case *apiistioioapitelemetryv1.Telemetry:
		return gvk.Telemetry, true
	case *sigsk8siogatewayapiapisv1alpha2.UDPRoute:
		return gvk.UDPRoute, true
	case *k8sioapiadmissionregistrationv1.ValidatingWebhookConfiguration:
		return gvk.ValidatingWebhookConfiguration, true
	case *istioioapinetworkingv1alpha3.VirtualService:
		return gvk.VirtualService, true
	case *apiistioioapinetworkingv1.VirtualService:
		return gvk.VirtualService, true
	case *istioioapiextensionsv1alpha1.WasmPlugin:
		return gvk.WasmPlugin, true
	case *apiistioioapiextensionsv1alpha1.WasmPlugin:
		return gvk.WasmPlugin, true
	case *istioioapinetworkingv1alpha3.WorkloadEntry:
		return gvk.WorkloadEntry, true
	case *apiistioioapinetworkingv1.WorkloadEntry:
		return gvk.WorkloadEntry, true
	case *istioioapinetworkingv1alpha3.WorkloadGroup:
		return gvk.WorkloadGroup, true
	case *apiistioioapinetworkingv1.WorkloadGroup:
		return gvk.WorkloadGroup, true
	default:
		return config.GroupVersionKind{}, false
	}
}
