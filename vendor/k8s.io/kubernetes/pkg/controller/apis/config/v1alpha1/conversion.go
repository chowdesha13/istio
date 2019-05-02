/*
Copyright 2018 The Kubernetes Authors.

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

package v1alpha1

import (
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/kube-controller-manager/config/v1alpha1"
	"k8s.io/kubernetes/pkg/controller/apis/config"
)

// Important! The public back-and-forth conversion functions for the types in this generic
// package with ComponentConfig types need to be manually exposed like this in order for
// other packages that reference this package to be able to call these conversion functions
// in an autogenerated manner.
// TODO: Fix the bug in conversion-gen so it automatically discovers these Convert_* functions
// in autogenerated code as well.

// Convert_v1alpha1_GenericControllerManagerConfiguration_To_config_GenericControllerManagerConfiguration is an autogenerated conversion function.
func Convert_v1alpha1_GenericControllerManagerConfiguration_To_config_GenericControllerManagerConfiguration(in *v1alpha1.GenericControllerManagerConfiguration, out *config.GenericControllerManagerConfiguration, s conversion.Scope) error {
	return autoConvert_v1alpha1_GenericControllerManagerConfiguration_To_config_GenericControllerManagerConfiguration(in, out, s)
}

// Convert_config_GenericControllerManagerConfiguration_To_v1alpha1_GenericControllerManagerConfiguration is an autogenerated conversion function.
func Convert_config_GenericControllerManagerConfiguration_To_v1alpha1_GenericControllerManagerConfiguration(in *config.GenericControllerManagerConfiguration, out *v1alpha1.GenericControllerManagerConfiguration, s conversion.Scope) error {
	return autoConvert_config_GenericControllerManagerConfiguration_To_v1alpha1_GenericControllerManagerConfiguration(in, out, s)
}

// Convert_v1alpha1_KubeCloudSharedConfiguration_To_config_KubeCloudSharedConfiguration is an autogenerated conversion function.
func Convert_v1alpha1_KubeCloudSharedConfiguration_To_config_KubeCloudSharedConfiguration(in *v1alpha1.KubeCloudSharedConfiguration, out *config.KubeCloudSharedConfiguration, s conversion.Scope) error {
	return autoConvert_v1alpha1_KubeCloudSharedConfiguration_To_config_KubeCloudSharedConfiguration(in, out, s)
}

// Convert_config_KubeCloudSharedConfiguration_To_v1alpha1_KubeCloudSharedConfiguration is an autogenerated conversion function.
func Convert_config_KubeCloudSharedConfiguration_To_v1alpha1_KubeCloudSharedConfiguration(in *config.KubeCloudSharedConfiguration, out *v1alpha1.KubeCloudSharedConfiguration, s conversion.Scope) error {
	return autoConvert_config_KubeCloudSharedConfiguration_To_v1alpha1_KubeCloudSharedConfiguration(in, out, s)
}

// Convert_v1alpha1_ServiceControllerConfiguration_To_config_ServiceControllerConfiguration is an autogenerated conversion function.
func Convert_v1alpha1_ServiceControllerConfiguration_To_config_ServiceControllerConfiguration(in *v1alpha1.ServiceControllerConfiguration, out *config.ServiceControllerConfiguration, s conversion.Scope) error {
	return autoConvert_v1alpha1_ServiceControllerConfiguration_To_config_ServiceControllerConfiguration(in, out, s)
}

// Convert_config_ServiceControllerConfiguration_To_v1alpha1_ServiceControllerConfiguration is an autogenerated conversion function.
func Convert_config_ServiceControllerConfiguration_To_v1alpha1_ServiceControllerConfiguration(in *config.ServiceControllerConfiguration, out *v1alpha1.ServiceControllerConfiguration, s conversion.Scope) error {
	return autoConvert_config_ServiceControllerConfiguration_To_v1alpha1_ServiceControllerConfiguration(in, out, s)
}
