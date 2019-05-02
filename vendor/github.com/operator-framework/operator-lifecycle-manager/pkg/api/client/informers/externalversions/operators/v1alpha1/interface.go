/*
Copyright 2019 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	internalinterfaces "github.com/operator-framework/operator-lifecycle-manager/pkg/api/client/informers/externalversions/internalinterfaces"
)

// Interface provides access to all the informers in this group version.
type Interface interface {
	// CatalogSources returns a CatalogSourceInformer.
	CatalogSources() CatalogSourceInformer
	// ClusterServiceVersions returns a ClusterServiceVersionInformer.
	ClusterServiceVersions() ClusterServiceVersionInformer
	// InstallPlans returns a InstallPlanInformer.
	InstallPlans() InstallPlanInformer
	// Subscriptions returns a SubscriptionInformer.
	Subscriptions() SubscriptionInformer
}

type version struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &version{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// CatalogSources returns a CatalogSourceInformer.
func (v *version) CatalogSources() CatalogSourceInformer {
	return &catalogSourceInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// ClusterServiceVersions returns a ClusterServiceVersionInformer.
func (v *version) ClusterServiceVersions() ClusterServiceVersionInformer {
	return &clusterServiceVersionInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// InstallPlans returns a InstallPlanInformer.
func (v *version) InstallPlans() InstallPlanInformer {
	return &installPlanInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}

// Subscriptions returns a SubscriptionInformer.
func (v *version) Subscriptions() SubscriptionInformer {
	return &subscriptionInformer{factory: v.factory, namespace: v.namespace, tweakListOptions: v.tweakListOptions}
}
