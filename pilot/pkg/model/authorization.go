// Copyright 2018 Istio Authors
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

package model

import (
	rbacproto "istio.io/api/rbac/v1alpha1"
	authpb "istio.io/api/security/v1beta1"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schemas"
	istiolog "istio.io/pkg/log"
)

var (
	rbacLog = istiolog.RegisterScope("rbac", "rbac debugging", 0)
)

// RolesAndBindings stores the the ServiceRole and ServiceRoleBinding in the same namespace.
type RolesAndBindings struct {
	// ServiceRoles in the same namespace.
	Roles []Config

	// ServiceRoleBindings indexed by its associated ServiceRole's name.
	Bindings map[string][]*rbacproto.ServiceRoleBinding
}

// AuthorizationPolicies organizes authorization policies by namespace.
type AuthorizationPolicies struct {
	// Maps from namespace to the v1alpha1 RBAC policies, deprecated by v1beta1 Authorization policy.
	namespaceToV1alpha1Policies map[string]*RolesAndBindings

	// The mesh global RbacConfig, deprecated by v1beta1 Authorization policy.
	rbacConfig *rbacproto.RbacConfig

	// Maps from namespace to the v1beta1 Authorization policies.
	namespaceToV1beta1Policies map[string][]Config
}

// GetAuthorizationPolicies gets the authorization policies in the mesh.
func GetAuthorizationPolicies(env *Environment) (*AuthorizationPolicies, error) {
	policy := &AuthorizationPolicies{
		namespaceToV1alpha1Policies: map[string]*RolesAndBindings{},
		namespaceToV1beta1Policies:  map[string][]Config{},
	}

	rbacConfig := env.IstioConfigStore.ClusterRbacConfig()
	if rbacConfig == nil {
		rbacConfig = env.IstioConfigStore.RbacConfig()
	}
	if rbacConfig != nil {
		policy.rbacConfig = rbacConfig.Spec.(*rbacproto.RbacConfig)
	}

	roles, err := env.List(schemas.ServiceRole.Type, NamespaceAll)
	if err != nil {
		return nil, err
	}
	policy.addServiceRoles(roles)

	bindings, err := env.List(schemas.ServiceRoleBinding.Type, NamespaceAll)
	if err != nil {
		return nil, err
	}
	policy.addServiceRoleBindings(bindings)

	policies, err := env.List(schemas.AuthorizationPolicy.Type, NamespaceAll)
	if err != nil {
		return nil, err
	}
	policy.addAuthorizationPolicies(policies)

	return policy, nil
}

// IsV1alpha1RBACEnabled returns true if RBAC is enabled for the service in the given namespace.
func (policy *AuthorizationPolicies) IsV1alpha1RBACEnabled(service string, namespace string) bool {
	if policy == nil || policy.rbacConfig == nil {
		return false
	}

	rbacConfig := policy.rbacConfig
	switch rbacConfig.Mode {
	case rbacproto.RbacConfig_ON:
		return true
	case rbacproto.RbacConfig_ON_WITH_INCLUSION:
		return isInRbacTargetList(service, namespace, rbacConfig.Inclusion)
	case rbacproto.RbacConfig_ON_WITH_EXCLUSION:
		return !isInRbacTargetList(service, namespace, rbacConfig.Exclusion)
	default:
		return false
	}
}

// IsGlobalPermissiveEnabled returns true if global permissive mode is enabled.
func (policy *AuthorizationPolicies) IsGlobalPermissiveEnabled() bool {
	return policy != nil && policy.rbacConfig != nil &&
		policy.rbacConfig.EnforcementMode == rbacproto.EnforcementMode_PERMISSIVE
}

// ListServiceRoles returns ServiceRole in the given namespace.
func (policy *AuthorizationPolicies) ListServiceRoles(ns string) []Config {
	if policy == nil {
		return nil
	}

	rolesAndBindings := policy.namespaceToV1alpha1Policies[ns]
	if rolesAndBindings == nil {
		return nil
	}
	return rolesAndBindings.Roles
}

// ListServiceRoleBindings returns the ServiceRoleBindings in the given namespace.
func (policy *AuthorizationPolicies) ListServiceRoleBindings(ns string) map[string][]*rbacproto.ServiceRoleBinding {
	if policy == nil {
		return map[string][]*rbacproto.ServiceRoleBinding{}
	}

	rolesAndBindings := policy.namespaceToV1alpha1Policies[ns]
	if rolesAndBindings == nil || rolesAndBindings.Bindings == nil {
		return map[string][]*rbacproto.ServiceRoleBinding{}
	}

	return rolesAndBindings.Bindings
}

// ListAuthorizationPolicies returns the AuthorizationPolicy for the workload in the given namespace.
func (policy *AuthorizationPolicies) ListAuthorizationPolicies(ns string, workloadLabels map[string]string) []Config {
	if policy == nil {
		return nil
	}

	var ret []Config
	workload := labels.Instance(workloadLabels)
	for _, config := range policy.namespaceToV1beta1Policies[ns] {
		spec := config.Spec.(*authpb.AuthorizationPolicy)
		matched := true
		if len(spec.GetSelector().GetMatchLabels()) > 0 {
			selector := labels.Instance(spec.Selector.MatchLabels)
			matched = selector.SubsetOf(workload)
		}
		if matched {
			ret = append(ret, config)
		}
	}

	return ret
}

func (policy *AuthorizationPolicies) addServiceRoles(roles []Config) {
	if policy == nil {
		return
	}
	for _, role := range roles {
		if policy.namespaceToV1alpha1Policies[role.Namespace] == nil {
			policy.namespaceToV1alpha1Policies[role.Namespace] = &RolesAndBindings{
				Bindings: map[string][]*rbacproto.ServiceRoleBinding{},
			}
		}
		rolesAndBindings := policy.namespaceToV1alpha1Policies[role.Namespace]
		rolesAndBindings.Roles = append(rolesAndBindings.Roles, role)
	}
}

func (policy *AuthorizationPolicies) addServiceRoleBindings(bindings []Config) {
	if policy == nil {
		return
	}

	for _, binding := range bindings {
		spec := binding.Spec.(*rbacproto.ServiceRoleBinding)
		name := spec.RoleRef.Name
		if name == "" {
			rbacLog.Errorf("ignored invalid binding %s in %s with empty RoleRef.Name",
				binding.Name, binding.Namespace)
			return
		}

		if policy.namespaceToV1alpha1Policies[binding.Namespace] == nil {
			policy.namespaceToV1alpha1Policies[binding.Namespace] = &RolesAndBindings{
				Bindings: map[string][]*rbacproto.ServiceRoleBinding{},
			}
		}
		rolesAndBindings := policy.namespaceToV1alpha1Policies[binding.Namespace]
		rolesAndBindings.Bindings[name] = append(
			rolesAndBindings.Bindings[name], binding.Spec.(*rbacproto.ServiceRoleBinding))
	}
}

func (policy *AuthorizationPolicies) addAuthorizationPolicies(configs []Config) {
	if policy == nil {
		return
	}

	for _, config := range configs {
		policy.namespaceToV1beta1Policies[config.Namespace] =
			append(policy.namespaceToV1beta1Policies[config.Namespace], config)
	}
}

// isInRbacTargetList checks if a given service and namespace is included in the RbacConfig target.
func isInRbacTargetList(serviceHostname string, namespace string, target *rbacproto.RbacConfig_Target) bool {
	if target == nil {
		return false
	}
	for _, ns := range target.Namespaces {
		if namespace == ns {
			return true
		}
	}
	for _, service := range target.Services {
		if service == serviceHostname {
			return true
		}
	}
	return false
}
