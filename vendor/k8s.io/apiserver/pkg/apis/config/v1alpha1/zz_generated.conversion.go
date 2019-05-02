// +build !ignore_autogenerated

/*
Copyright The Kubernetes Authors.

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

// Code generated by conversion-gen. DO NOT EDIT.

package v1alpha1

import (
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	conversion "k8s.io/apimachinery/pkg/conversion"
	runtime "k8s.io/apimachinery/pkg/runtime"
	config "k8s.io/apiserver/pkg/apis/config"
)

func init() {
	localSchemeBuilder.Register(RegisterConversions)
}

// RegisterConversions adds conversion functions to the given scheme.
// Public to allow building arbitrary schemes.
func RegisterConversions(s *runtime.Scheme) error {
	if err := s.AddGeneratedConversionFunc((*DebuggingConfiguration)(nil), (*config.DebuggingConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_DebuggingConfiguration_To_config_DebuggingConfiguration(a.(*DebuggingConfiguration), b.(*config.DebuggingConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*config.DebuggingConfiguration)(nil), (*DebuggingConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_config_DebuggingConfiguration_To_v1alpha1_DebuggingConfiguration(a.(*config.DebuggingConfiguration), b.(*DebuggingConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*LeaderElectionConfiguration)(nil), (*config.LeaderElectionConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LeaderElectionConfiguration_To_config_LeaderElectionConfiguration(a.(*LeaderElectionConfiguration), b.(*config.LeaderElectionConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddGeneratedConversionFunc((*config.LeaderElectionConfiguration)(nil), (*LeaderElectionConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_config_LeaderElectionConfiguration_To_v1alpha1_LeaderElectionConfiguration(a.(*config.LeaderElectionConfiguration), b.(*LeaderElectionConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddConversionFunc((*config.DebuggingConfiguration)(nil), (*DebuggingConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_config_DebuggingConfiguration_To_v1alpha1_DebuggingConfiguration(a.(*config.DebuggingConfiguration), b.(*DebuggingConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddConversionFunc((*config.LeaderElectionConfiguration)(nil), (*LeaderElectionConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_config_LeaderElectionConfiguration_To_v1alpha1_LeaderElectionConfiguration(a.(*config.LeaderElectionConfiguration), b.(*LeaderElectionConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddConversionFunc((*DebuggingConfiguration)(nil), (*config.DebuggingConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_DebuggingConfiguration_To_config_DebuggingConfiguration(a.(*DebuggingConfiguration), b.(*config.DebuggingConfiguration), scope)
	}); err != nil {
		return err
	}
	if err := s.AddConversionFunc((*LeaderElectionConfiguration)(nil), (*config.LeaderElectionConfiguration)(nil), func(a, b interface{}, scope conversion.Scope) error {
		return Convert_v1alpha1_LeaderElectionConfiguration_To_config_LeaderElectionConfiguration(a.(*LeaderElectionConfiguration), b.(*config.LeaderElectionConfiguration), scope)
	}); err != nil {
		return err
	}
	return nil
}

func autoConvert_v1alpha1_DebuggingConfiguration_To_config_DebuggingConfiguration(in *DebuggingConfiguration, out *config.DebuggingConfiguration, s conversion.Scope) error {
	out.EnableProfiling = in.EnableProfiling
	out.EnableContentionProfiling = in.EnableContentionProfiling
	return nil
}

func autoConvert_config_DebuggingConfiguration_To_v1alpha1_DebuggingConfiguration(in *config.DebuggingConfiguration, out *DebuggingConfiguration, s conversion.Scope) error {
	out.EnableProfiling = in.EnableProfiling
	out.EnableContentionProfiling = in.EnableContentionProfiling
	return nil
}

func autoConvert_v1alpha1_LeaderElectionConfiguration_To_config_LeaderElectionConfiguration(in *LeaderElectionConfiguration, out *config.LeaderElectionConfiguration, s conversion.Scope) error {
	if err := v1.Convert_Pointer_bool_To_bool(&in.LeaderElect, &out.LeaderElect, s); err != nil {
		return err
	}
	out.LeaseDuration = in.LeaseDuration
	out.RenewDeadline = in.RenewDeadline
	out.RetryPeriod = in.RetryPeriod
	out.ResourceLock = in.ResourceLock
	return nil
}

func autoConvert_config_LeaderElectionConfiguration_To_v1alpha1_LeaderElectionConfiguration(in *config.LeaderElectionConfiguration, out *LeaderElectionConfiguration, s conversion.Scope) error {
	if err := v1.Convert_bool_To_Pointer_bool(&in.LeaderElect, &out.LeaderElect, s); err != nil {
		return err
	}
	out.LeaseDuration = in.LeaseDuration
	out.RenewDeadline = in.RenewDeadline
	out.RetryPeriod = in.RetryPeriod
	out.ResourceLock = in.ResourceLock
	return nil
}
