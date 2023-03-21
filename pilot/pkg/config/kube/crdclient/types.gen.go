// GENERATED FILE -- DO NOT EDIT
//

package crdclient

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube"

	k8sioapiadmissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	k8sioapiappsv1 "k8s.io/api/apps/v1"
	k8sioapicertificatesv1 "k8s.io/api/certificates/v1"
	k8sioapicorev1 "k8s.io/api/core/v1"
	k8sioapidiscoveryv1 "k8s.io/api/discovery/v1"
	k8sioapinetworkingv1 "k8s.io/api/networking/v1"
	k8sioapiextensionsapiserverpkgapisapiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	sigsk8siogatewayapiapisv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	sigsk8siogatewayapiapisv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	istioioapiextensionsv1alpha1 "istio.io/api/extensions/v1alpha1"
	istioioapimetav1alpha1 "istio.io/api/meta/v1alpha1"
	istioioapinetworkingv1alpha3 "istio.io/api/networking/v1alpha3"
	istioioapinetworkingv1beta1 "istio.io/api/networking/v1beta1"
	istioioapisecurityv1beta1 "istio.io/api/security/v1beta1"
	istioioapitelemetryv1alpha1 "istio.io/api/telemetry/v1alpha1"
	apiistioioapiextensionsv1alpha1 "istio.io/client-go/pkg/apis/extensions/v1alpha1"
	apiistioioapinetworkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	apiistioioapinetworkingv1beta1 "istio.io/client-go/pkg/apis/networking/v1beta1"
	apiistioioapisecurityv1beta1 "istio.io/client-go/pkg/apis/security/v1beta1"
	apiistioioapitelemetryv1alpha1 "istio.io/client-go/pkg/apis/telemetry/v1alpha1"
)

func create(c kube.Client, cfg config.Config, objMeta metav1.ObjectMeta) (metav1.Object, error) {
	switch cfg.GroupVersionKind {
	case gvk.AuthorizationPolicy:
		return c.Istio().SecurityV1beta1().AuthorizationPolicies(cfg.Namespace).Create(context.TODO(), &apiistioioapisecurityv1beta1.AuthorizationPolicy{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapisecurityv1beta1.AuthorizationPolicy)),
		}, metav1.CreateOptions{})
	case gvk.DestinationRule:
		return c.Istio().NetworkingV1alpha3().DestinationRules(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.DestinationRule{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.DestinationRule)),
		}, metav1.CreateOptions{})
	case gvk.EnvoyFilter:
		return c.Istio().NetworkingV1alpha3().EnvoyFilters(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.EnvoyFilter{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.EnvoyFilter)),
		}, metav1.CreateOptions{})
	case gvk.GRPCRoute:
		return c.GatewayAPI().GatewayV1alpha2().GRPCRoutes(cfg.Namespace).Create(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.GRPCRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.GRPCRouteSpec)),
		}, metav1.CreateOptions{})
	case gvk.Gateway:
		return c.Istio().NetworkingV1alpha3().Gateways(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.Gateway{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.Gateway)),
		}, metav1.CreateOptions{})
	case gvk.GatewayClass:
		return c.GatewayAPI().GatewayV1beta1().GatewayClasses().Create(context.TODO(), &sigsk8siogatewayapiapisv1beta1.GatewayClass{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewayClassSpec)),
		}, metav1.CreateOptions{})
	case gvk.HTTPRoute:
		return c.GatewayAPI().GatewayV1beta1().HTTPRoutes(cfg.Namespace).Create(context.TODO(), &sigsk8siogatewayapiapisv1beta1.HTTPRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1beta1.HTTPRouteSpec)),
		}, metav1.CreateOptions{})
	case gvk.KubernetesGateway:
		return c.GatewayAPI().GatewayV1beta1().Gateways(cfg.Namespace).Create(context.TODO(), &sigsk8siogatewayapiapisv1beta1.Gateway{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewaySpec)),
		}, metav1.CreateOptions{})
	case gvk.PeerAuthentication:
		return c.Istio().SecurityV1beta1().PeerAuthentications(cfg.Namespace).Create(context.TODO(), &apiistioioapisecurityv1beta1.PeerAuthentication{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapisecurityv1beta1.PeerAuthentication)),
		}, metav1.CreateOptions{})
	case gvk.ProxyConfig:
		return c.Istio().NetworkingV1beta1().ProxyConfigs(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1beta1.ProxyConfig{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1beta1.ProxyConfig)),
		}, metav1.CreateOptions{})
	case gvk.ReferenceGrant:
		return c.GatewayAPI().GatewayV1alpha2().ReferenceGrants(cfg.Namespace).Create(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.ReferenceGrant{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.ReferenceGrantSpec)),
		}, metav1.CreateOptions{})
	case gvk.RequestAuthentication:
		return c.Istio().SecurityV1beta1().RequestAuthentications(cfg.Namespace).Create(context.TODO(), &apiistioioapisecurityv1beta1.RequestAuthentication{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapisecurityv1beta1.RequestAuthentication)),
		}, metav1.CreateOptions{})
	case gvk.ServiceEntry:
		return c.Istio().NetworkingV1alpha3().ServiceEntries(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.ServiceEntry{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.ServiceEntry)),
		}, metav1.CreateOptions{})
	case gvk.Sidecar:
		return c.Istio().NetworkingV1alpha3().Sidecars(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.Sidecar{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.Sidecar)),
		}, metav1.CreateOptions{})
	case gvk.TCPRoute:
		return c.GatewayAPI().GatewayV1alpha2().TCPRoutes(cfg.Namespace).Create(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.TCPRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.TCPRouteSpec)),
		}, metav1.CreateOptions{})
	case gvk.TLSRoute:
		return c.GatewayAPI().GatewayV1alpha2().TLSRoutes(cfg.Namespace).Create(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.TLSRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.TLSRouteSpec)),
		}, metav1.CreateOptions{})
	case gvk.Telemetry:
		return c.Istio().TelemetryV1alpha1().Telemetries(cfg.Namespace).Create(context.TODO(), &apiistioioapitelemetryv1alpha1.Telemetry{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapitelemetryv1alpha1.Telemetry)),
		}, metav1.CreateOptions{})
	case gvk.UDPRoute:
		return c.GatewayAPI().GatewayV1alpha2().UDPRoutes(cfg.Namespace).Create(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.UDPRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.UDPRouteSpec)),
		}, metav1.CreateOptions{})
	case gvk.VirtualService:
		return c.Istio().NetworkingV1alpha3().VirtualServices(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.VirtualService{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.VirtualService)),
		}, metav1.CreateOptions{})
	case gvk.WasmPlugin:
		return c.Istio().ExtensionsV1alpha1().WasmPlugins(cfg.Namespace).Create(context.TODO(), &apiistioioapiextensionsv1alpha1.WasmPlugin{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapiextensionsv1alpha1.WasmPlugin)),
		}, metav1.CreateOptions{})
	case gvk.WorkloadEntry:
		return c.Istio().NetworkingV1alpha3().WorkloadEntries(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.WorkloadEntry{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.WorkloadEntry)),
		}, metav1.CreateOptions{})
	case gvk.WorkloadGroup:
		return c.Istio().NetworkingV1alpha3().WorkloadGroups(cfg.Namespace).Create(context.TODO(), &apiistioioapinetworkingv1alpha3.WorkloadGroup{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.WorkloadGroup)),
		}, metav1.CreateOptions{})
	default:
		return nil, fmt.Errorf("unsupported type: %v", cfg.GroupVersionKind)
	}
}

func update(c kube.Client, cfg config.Config, objMeta metav1.ObjectMeta) (metav1.Object, error) {
	switch cfg.GroupVersionKind {
	case gvk.AuthorizationPolicy:
		return c.Istio().SecurityV1beta1().AuthorizationPolicies(cfg.Namespace).Update(context.TODO(), &apiistioioapisecurityv1beta1.AuthorizationPolicy{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapisecurityv1beta1.AuthorizationPolicy)),
		}, metav1.UpdateOptions{})
	case gvk.DestinationRule:
		return c.Istio().NetworkingV1alpha3().DestinationRules(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.DestinationRule{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.DestinationRule)),
		}, metav1.UpdateOptions{})
	case gvk.EnvoyFilter:
		return c.Istio().NetworkingV1alpha3().EnvoyFilters(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.EnvoyFilter{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.EnvoyFilter)),
		}, metav1.UpdateOptions{})
	case gvk.GRPCRoute:
		return c.GatewayAPI().GatewayV1alpha2().GRPCRoutes(cfg.Namespace).Update(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.GRPCRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.GRPCRouteSpec)),
		}, metav1.UpdateOptions{})
	case gvk.Gateway:
		return c.Istio().NetworkingV1alpha3().Gateways(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.Gateway{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.Gateway)),
		}, metav1.UpdateOptions{})
	case gvk.GatewayClass:
		return c.GatewayAPI().GatewayV1beta1().GatewayClasses().Update(context.TODO(), &sigsk8siogatewayapiapisv1beta1.GatewayClass{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewayClassSpec)),
		}, metav1.UpdateOptions{})
	case gvk.HTTPRoute:
		return c.GatewayAPI().GatewayV1beta1().HTTPRoutes(cfg.Namespace).Update(context.TODO(), &sigsk8siogatewayapiapisv1beta1.HTTPRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1beta1.HTTPRouteSpec)),
		}, metav1.UpdateOptions{})
	case gvk.KubernetesGateway:
		return c.GatewayAPI().GatewayV1beta1().Gateways(cfg.Namespace).Update(context.TODO(), &sigsk8siogatewayapiapisv1beta1.Gateway{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewaySpec)),
		}, metav1.UpdateOptions{})
	case gvk.PeerAuthentication:
		return c.Istio().SecurityV1beta1().PeerAuthentications(cfg.Namespace).Update(context.TODO(), &apiistioioapisecurityv1beta1.PeerAuthentication{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapisecurityv1beta1.PeerAuthentication)),
		}, metav1.UpdateOptions{})
	case gvk.ProxyConfig:
		return c.Istio().NetworkingV1beta1().ProxyConfigs(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1beta1.ProxyConfig{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1beta1.ProxyConfig)),
		}, metav1.UpdateOptions{})
	case gvk.ReferenceGrant:
		return c.GatewayAPI().GatewayV1alpha2().ReferenceGrants(cfg.Namespace).Update(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.ReferenceGrant{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.ReferenceGrantSpec)),
		}, metav1.UpdateOptions{})
	case gvk.RequestAuthentication:
		return c.Istio().SecurityV1beta1().RequestAuthentications(cfg.Namespace).Update(context.TODO(), &apiistioioapisecurityv1beta1.RequestAuthentication{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapisecurityv1beta1.RequestAuthentication)),
		}, metav1.UpdateOptions{})
	case gvk.ServiceEntry:
		return c.Istio().NetworkingV1alpha3().ServiceEntries(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.ServiceEntry{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.ServiceEntry)),
		}, metav1.UpdateOptions{})
	case gvk.Sidecar:
		return c.Istio().NetworkingV1alpha3().Sidecars(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.Sidecar{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.Sidecar)),
		}, metav1.UpdateOptions{})
	case gvk.TCPRoute:
		return c.GatewayAPI().GatewayV1alpha2().TCPRoutes(cfg.Namespace).Update(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.TCPRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.TCPRouteSpec)),
		}, metav1.UpdateOptions{})
	case gvk.TLSRoute:
		return c.GatewayAPI().GatewayV1alpha2().TLSRoutes(cfg.Namespace).Update(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.TLSRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.TLSRouteSpec)),
		}, metav1.UpdateOptions{})
	case gvk.Telemetry:
		return c.Istio().TelemetryV1alpha1().Telemetries(cfg.Namespace).Update(context.TODO(), &apiistioioapitelemetryv1alpha1.Telemetry{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapitelemetryv1alpha1.Telemetry)),
		}, metav1.UpdateOptions{})
	case gvk.UDPRoute:
		return c.GatewayAPI().GatewayV1alpha2().UDPRoutes(cfg.Namespace).Update(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.UDPRoute{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*sigsk8siogatewayapiapisv1alpha2.UDPRouteSpec)),
		}, metav1.UpdateOptions{})
	case gvk.VirtualService:
		return c.Istio().NetworkingV1alpha3().VirtualServices(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.VirtualService{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.VirtualService)),
		}, metav1.UpdateOptions{})
	case gvk.WasmPlugin:
		return c.Istio().ExtensionsV1alpha1().WasmPlugins(cfg.Namespace).Update(context.TODO(), &apiistioioapiextensionsv1alpha1.WasmPlugin{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapiextensionsv1alpha1.WasmPlugin)),
		}, metav1.UpdateOptions{})
	case gvk.WorkloadEntry:
		return c.Istio().NetworkingV1alpha3().WorkloadEntries(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.WorkloadEntry{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.WorkloadEntry)),
		}, metav1.UpdateOptions{})
	case gvk.WorkloadGroup:
		return c.Istio().NetworkingV1alpha3().WorkloadGroups(cfg.Namespace).Update(context.TODO(), &apiistioioapinetworkingv1alpha3.WorkloadGroup{
			ObjectMeta: objMeta,
			Spec:       *(cfg.Spec.(*istioioapinetworkingv1alpha3.WorkloadGroup)),
		}, metav1.UpdateOptions{})
	default:
		return nil, fmt.Errorf("unsupported type: %v", cfg.GroupVersionKind)
	}
}

func updateStatus(c kube.Client, cfg config.Config, objMeta metav1.ObjectMeta) (metav1.Object, error) {
	switch cfg.GroupVersionKind {
	case gvk.AuthorizationPolicy:
		return c.Istio().SecurityV1beta1().AuthorizationPolicies(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapisecurityv1beta1.AuthorizationPolicy{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.DestinationRule:
		return c.Istio().NetworkingV1alpha3().DestinationRules(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.DestinationRule{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.EnvoyFilter:
		return c.Istio().NetworkingV1alpha3().EnvoyFilters(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.EnvoyFilter{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.GRPCRoute:
		return c.GatewayAPI().GatewayV1alpha2().GRPCRoutes(cfg.Namespace).UpdateStatus(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.GRPCRoute{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*sigsk8siogatewayapiapisv1alpha2.GRPCRouteStatus)),
		}, metav1.UpdateOptions{})
	case gvk.Gateway:
		return c.Istio().NetworkingV1alpha3().Gateways(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.Gateway{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.GatewayClass:
		return c.GatewayAPI().GatewayV1beta1().GatewayClasses().UpdateStatus(context.TODO(), &sigsk8siogatewayapiapisv1beta1.GatewayClass{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*sigsk8siogatewayapiapisv1beta1.GatewayClassStatus)),
		}, metav1.UpdateOptions{})
	case gvk.HTTPRoute:
		return c.GatewayAPI().GatewayV1beta1().HTTPRoutes(cfg.Namespace).UpdateStatus(context.TODO(), &sigsk8siogatewayapiapisv1beta1.HTTPRoute{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*sigsk8siogatewayapiapisv1beta1.HTTPRouteStatus)),
		}, metav1.UpdateOptions{})
	case gvk.KubernetesGateway:
		return c.GatewayAPI().GatewayV1beta1().Gateways(cfg.Namespace).UpdateStatus(context.TODO(), &sigsk8siogatewayapiapisv1beta1.Gateway{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*sigsk8siogatewayapiapisv1beta1.GatewayStatus)),
		}, metav1.UpdateOptions{})
	case gvk.PeerAuthentication:
		return c.Istio().SecurityV1beta1().PeerAuthentications(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapisecurityv1beta1.PeerAuthentication{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.ProxyConfig:
		return c.Istio().NetworkingV1beta1().ProxyConfigs(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1beta1.ProxyConfig{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.RequestAuthentication:
		return c.Istio().SecurityV1beta1().RequestAuthentications(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapisecurityv1beta1.RequestAuthentication{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.ServiceEntry:
		return c.Istio().NetworkingV1alpha3().ServiceEntries(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.ServiceEntry{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.Sidecar:
		return c.Istio().NetworkingV1alpha3().Sidecars(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.Sidecar{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.TCPRoute:
		return c.GatewayAPI().GatewayV1alpha2().TCPRoutes(cfg.Namespace).UpdateStatus(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.TCPRoute{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*sigsk8siogatewayapiapisv1alpha2.TCPRouteStatus)),
		}, metav1.UpdateOptions{})
	case gvk.TLSRoute:
		return c.GatewayAPI().GatewayV1alpha2().TLSRoutes(cfg.Namespace).UpdateStatus(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.TLSRoute{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*sigsk8siogatewayapiapisv1alpha2.TLSRouteStatus)),
		}, metav1.UpdateOptions{})
	case gvk.Telemetry:
		return c.Istio().TelemetryV1alpha1().Telemetries(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapitelemetryv1alpha1.Telemetry{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.UDPRoute:
		return c.GatewayAPI().GatewayV1alpha2().UDPRoutes(cfg.Namespace).UpdateStatus(context.TODO(), &sigsk8siogatewayapiapisv1alpha2.UDPRoute{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*sigsk8siogatewayapiapisv1alpha2.UDPRouteStatus)),
		}, metav1.UpdateOptions{})
	case gvk.VirtualService:
		return c.Istio().NetworkingV1alpha3().VirtualServices(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.VirtualService{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.WasmPlugin:
		return c.Istio().ExtensionsV1alpha1().WasmPlugins(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapiextensionsv1alpha1.WasmPlugin{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.WorkloadEntry:
		return c.Istio().NetworkingV1alpha3().WorkloadEntries(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.WorkloadEntry{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	case gvk.WorkloadGroup:
		return c.Istio().NetworkingV1alpha3().WorkloadGroups(cfg.Namespace).UpdateStatus(context.TODO(), &apiistioioapinetworkingv1alpha3.WorkloadGroup{
			ObjectMeta: objMeta,
			Status:     *(cfg.Status.(*istioioapimetav1alpha1.IstioStatus)),
		}, metav1.UpdateOptions{})
	default:
		return nil, fmt.Errorf("unsupported type: %v", cfg.GroupVersionKind)
	}
}

func patch(c kube.Client, orig config.Config, origMeta metav1.ObjectMeta, mod config.Config, modMeta metav1.ObjectMeta, typ types.PatchType) (metav1.Object, error) {
	if orig.GroupVersionKind != mod.GroupVersionKind {
		return nil, fmt.Errorf("gvk mismatch: %v, modified: %v", orig.GroupVersionKind, mod.GroupVersionKind)
	}
	switch orig.GroupVersionKind {
	case gvk.AuthorizationPolicy:
		oldRes := &apiistioioapisecurityv1beta1.AuthorizationPolicy{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapisecurityv1beta1.AuthorizationPolicy)),
		}
		modRes := &apiistioioapisecurityv1beta1.AuthorizationPolicy{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapisecurityv1beta1.AuthorizationPolicy)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().SecurityV1beta1().AuthorizationPolicies(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.DestinationRule:
		oldRes := &apiistioioapinetworkingv1alpha3.DestinationRule{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.DestinationRule)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.DestinationRule{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.DestinationRule)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().DestinationRules(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.EnvoyFilter:
		oldRes := &apiistioioapinetworkingv1alpha3.EnvoyFilter{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.EnvoyFilter)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.EnvoyFilter{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.EnvoyFilter)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().EnvoyFilters(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.GRPCRoute:
		oldRes := &sigsk8siogatewayapiapisv1alpha2.GRPCRoute{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1alpha2.GRPCRouteSpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1alpha2.GRPCRoute{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1alpha2.GRPCRouteSpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1alpha2().GRPCRoutes(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.Gateway:
		oldRes := &apiistioioapinetworkingv1alpha3.Gateway{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.Gateway)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.Gateway{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.Gateway)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().Gateways(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.GatewayClass:
		oldRes := &sigsk8siogatewayapiapisv1beta1.GatewayClass{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewayClassSpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1beta1.GatewayClass{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewayClassSpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1beta1().GatewayClasses().
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.HTTPRoute:
		oldRes := &sigsk8siogatewayapiapisv1beta1.HTTPRoute{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1beta1.HTTPRouteSpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1beta1.HTTPRoute{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1beta1.HTTPRouteSpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1beta1().HTTPRoutes(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.KubernetesGateway:
		oldRes := &sigsk8siogatewayapiapisv1beta1.Gateway{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewaySpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1beta1.Gateway{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1beta1.GatewaySpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1beta1().Gateways(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.PeerAuthentication:
		oldRes := &apiistioioapisecurityv1beta1.PeerAuthentication{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapisecurityv1beta1.PeerAuthentication)),
		}
		modRes := &apiistioioapisecurityv1beta1.PeerAuthentication{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapisecurityv1beta1.PeerAuthentication)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().SecurityV1beta1().PeerAuthentications(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.ProxyConfig:
		oldRes := &apiistioioapinetworkingv1beta1.ProxyConfig{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1beta1.ProxyConfig)),
		}
		modRes := &apiistioioapinetworkingv1beta1.ProxyConfig{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1beta1.ProxyConfig)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1beta1().ProxyConfigs(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.ReferenceGrant:
		oldRes := &sigsk8siogatewayapiapisv1alpha2.ReferenceGrant{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1alpha2.ReferenceGrantSpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1alpha2.ReferenceGrant{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1alpha2.ReferenceGrantSpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1alpha2().ReferenceGrants(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.RequestAuthentication:
		oldRes := &apiistioioapisecurityv1beta1.RequestAuthentication{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapisecurityv1beta1.RequestAuthentication)),
		}
		modRes := &apiistioioapisecurityv1beta1.RequestAuthentication{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapisecurityv1beta1.RequestAuthentication)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().SecurityV1beta1().RequestAuthentications(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.ServiceEntry:
		oldRes := &apiistioioapinetworkingv1alpha3.ServiceEntry{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.ServiceEntry)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.ServiceEntry{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.ServiceEntry)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().ServiceEntries(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.Sidecar:
		oldRes := &apiistioioapinetworkingv1alpha3.Sidecar{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.Sidecar)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.Sidecar{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.Sidecar)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().Sidecars(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.TCPRoute:
		oldRes := &sigsk8siogatewayapiapisv1alpha2.TCPRoute{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1alpha2.TCPRouteSpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1alpha2.TCPRoute{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1alpha2.TCPRouteSpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1alpha2().TCPRoutes(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.TLSRoute:
		oldRes := &sigsk8siogatewayapiapisv1alpha2.TLSRoute{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1alpha2.TLSRouteSpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1alpha2.TLSRoute{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1alpha2.TLSRouteSpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1alpha2().TLSRoutes(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.Telemetry:
		oldRes := &apiistioioapitelemetryv1alpha1.Telemetry{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapitelemetryv1alpha1.Telemetry)),
		}
		modRes := &apiistioioapitelemetryv1alpha1.Telemetry{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapitelemetryv1alpha1.Telemetry)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().TelemetryV1alpha1().Telemetries(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.UDPRoute:
		oldRes := &sigsk8siogatewayapiapisv1alpha2.UDPRoute{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*sigsk8siogatewayapiapisv1alpha2.UDPRouteSpec)),
		}
		modRes := &sigsk8siogatewayapiapisv1alpha2.UDPRoute{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*sigsk8siogatewayapiapisv1alpha2.UDPRouteSpec)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.GatewayAPI().GatewayV1alpha2().UDPRoutes(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.VirtualService:
		oldRes := &apiistioioapinetworkingv1alpha3.VirtualService{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.VirtualService)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.VirtualService{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.VirtualService)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().VirtualServices(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.WasmPlugin:
		oldRes := &apiistioioapiextensionsv1alpha1.WasmPlugin{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapiextensionsv1alpha1.WasmPlugin)),
		}
		modRes := &apiistioioapiextensionsv1alpha1.WasmPlugin{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapiextensionsv1alpha1.WasmPlugin)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().ExtensionsV1alpha1().WasmPlugins(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.WorkloadEntry:
		oldRes := &apiistioioapinetworkingv1alpha3.WorkloadEntry{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.WorkloadEntry)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.WorkloadEntry{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.WorkloadEntry)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().WorkloadEntries(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	case gvk.WorkloadGroup:
		oldRes := &apiistioioapinetworkingv1alpha3.WorkloadGroup{
			ObjectMeta: origMeta,
			Spec:       *(orig.Spec.(*istioioapinetworkingv1alpha3.WorkloadGroup)),
		}
		modRes := &apiistioioapinetworkingv1alpha3.WorkloadGroup{
			ObjectMeta: modMeta,
			Spec:       *(mod.Spec.(*istioioapinetworkingv1alpha3.WorkloadGroup)),
		}
		patchBytes, err := genPatchBytes(oldRes, modRes, typ)
		if err != nil {
			return nil, err
		}
		return c.Istio().NetworkingV1alpha3().WorkloadGroups(orig.Namespace).
			Patch(context.TODO(), orig.Name, typ, patchBytes, metav1.PatchOptions{FieldManager: "pilot-discovery"})
	default:
		return nil, fmt.Errorf("unsupported type: %v", orig.GroupVersionKind)
	}
}

func delete(c kube.Client, typ config.GroupVersionKind, name, namespace string, resourceVersion *string) error {
	var deleteOptions metav1.DeleteOptions
	if resourceVersion != nil {
		deleteOptions.Preconditions = &metav1.Preconditions{ResourceVersion: resourceVersion}
	}
	switch typ {
	case gvk.AuthorizationPolicy:
		return c.Istio().SecurityV1beta1().AuthorizationPolicies(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.DestinationRule:
		return c.Istio().NetworkingV1alpha3().DestinationRules(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.EnvoyFilter:
		return c.Istio().NetworkingV1alpha3().EnvoyFilters(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.GRPCRoute:
		return c.GatewayAPI().GatewayV1alpha2().GRPCRoutes(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.Gateway:
		return c.Istio().NetworkingV1alpha3().Gateways(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.GatewayClass:
		return c.GatewayAPI().GatewayV1beta1().GatewayClasses().Delete(context.TODO(), name, deleteOptions)
	case gvk.HTTPRoute:
		return c.GatewayAPI().GatewayV1beta1().HTTPRoutes(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.KubernetesGateway:
		return c.GatewayAPI().GatewayV1beta1().Gateways(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.PeerAuthentication:
		return c.Istio().SecurityV1beta1().PeerAuthentications(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.ProxyConfig:
		return c.Istio().NetworkingV1beta1().ProxyConfigs(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.ReferenceGrant:
		return c.GatewayAPI().GatewayV1alpha2().ReferenceGrants(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.RequestAuthentication:
		return c.Istio().SecurityV1beta1().RequestAuthentications(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.ServiceEntry:
		return c.Istio().NetworkingV1alpha3().ServiceEntries(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.Sidecar:
		return c.Istio().NetworkingV1alpha3().Sidecars(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.TCPRoute:
		return c.GatewayAPI().GatewayV1alpha2().TCPRoutes(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.TLSRoute:
		return c.GatewayAPI().GatewayV1alpha2().TLSRoutes(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.Telemetry:
		return c.Istio().TelemetryV1alpha1().Telemetries(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.UDPRoute:
		return c.GatewayAPI().GatewayV1alpha2().UDPRoutes(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.VirtualService:
		return c.Istio().NetworkingV1alpha3().VirtualServices(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.WasmPlugin:
		return c.Istio().ExtensionsV1alpha1().WasmPlugins(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.WorkloadEntry:
		return c.Istio().NetworkingV1alpha3().WorkloadEntries(namespace).Delete(context.TODO(), name, deleteOptions)
	case gvk.WorkloadGroup:
		return c.Istio().NetworkingV1alpha3().WorkloadGroups(namespace).Delete(context.TODO(), name, deleteOptions)
	default:
		return fmt.Errorf("unsupported type: %v", typ)
	}
}

var translationMap = map[config.GroupVersionKind]func(r runtime.Object) config.Config{
	gvk.AuthorizationPolicy: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapisecurityv1beta1.AuthorizationPolicy)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.AuthorizationPolicy,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.CertificateSigningRequest: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicertificatesv1.CertificateSigningRequest)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.CertificateSigningRequest,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.ConfigMap: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.ConfigMap)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.ConfigMap,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: obj,
		}
	},
	gvk.CustomResourceDefinition: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapiextensionsapiserverpkgapisapiextensionsv1.CustomResourceDefinition)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.CustomResourceDefinition,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.Deployment: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapiappsv1.Deployment)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Deployment,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.DestinationRule: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.DestinationRule)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.DestinationRule,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.EndpointSlice: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapidiscoveryv1.EndpointSlice)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.EndpointSlice,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: obj,
		}
	},
	gvk.Endpoints: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.Endpoints)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Endpoints,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: obj,
		}
	},
	gvk.EnvoyFilter: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.EnvoyFilter)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.EnvoyFilter,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.GRPCRoute: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1alpha2.GRPCRoute)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.GRPCRoute,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.Gateway: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.Gateway)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Gateway,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.GatewayClass: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1beta1.GatewayClass)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.GatewayClass,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.HTTPRoute: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1beta1.HTTPRoute)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.HTTPRoute,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.Ingress: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapinetworkingv1.Ingress)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Ingress,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.IngressClass: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapinetworkingv1.IngressClass)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.IngressClass,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.KubernetesGateway: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1beta1.Gateway)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.KubernetesGateway,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.MutatingWebhookConfiguration: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapiadmissionregistrationv1.MutatingWebhookConfiguration)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.MutatingWebhookConfiguration,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: obj,
		}
	},
	gvk.Namespace: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.Namespace)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Namespace,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.Node: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.Node)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Node,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.PeerAuthentication: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapisecurityv1beta1.PeerAuthentication)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.PeerAuthentication,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.Pod: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.Pod)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Pod,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.ProxyConfig: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1beta1.ProxyConfig)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.ProxyConfig,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.ReferenceGrant: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1alpha2.ReferenceGrant)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.ReferenceGrant,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.RequestAuthentication: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapisecurityv1beta1.RequestAuthentication)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.RequestAuthentication,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.Secret: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.Secret)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Secret,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: obj,
		}
	},
	gvk.Service: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.Service)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Service,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: &obj.Spec,
		}
	},
	gvk.ServiceAccount: func(r runtime.Object) config.Config {
		obj := r.(*k8sioapicorev1.ServiceAccount)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.ServiceAccount,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec: obj,
		}
	},
	gvk.ServiceEntry: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.ServiceEntry)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.ServiceEntry,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.Sidecar: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.Sidecar)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Sidecar,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.TCPRoute: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1alpha2.TCPRoute)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.TCPRoute,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.TLSRoute: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1alpha2.TLSRoute)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.TLSRoute,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.Telemetry: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapitelemetryv1alpha1.Telemetry)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.Telemetry,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.UDPRoute: func(r runtime.Object) config.Config {
		obj := r.(*sigsk8siogatewayapiapisv1alpha2.UDPRoute)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.UDPRoute,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.VirtualService: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.VirtualService)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.VirtualService,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.WasmPlugin: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapiextensionsv1alpha1.WasmPlugin)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.WasmPlugin,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.WorkloadEntry: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.WorkloadEntry)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.WorkloadEntry,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
	gvk.WorkloadGroup: func(r runtime.Object) config.Config {
		obj := r.(*apiistioioapinetworkingv1alpha3.WorkloadGroup)
		return config.Config{
			Meta: config.Meta{
				GroupVersionKind:  gvk.WorkloadGroup,
				Name:              obj.Name,
				Namespace:         obj.Namespace,
				Labels:            obj.Labels,
				Annotations:       obj.Annotations,
				ResourceVersion:   obj.ResourceVersion,
				CreationTimestamp: obj.CreationTimestamp.Time,
				OwnerReferences:   obj.OwnerReferences,
				UID:               string(obj.UID),
				Generation:        obj.Generation,
			},
			Spec:   &obj.Spec,
			Status: &obj.Status,
		}
	},
}
