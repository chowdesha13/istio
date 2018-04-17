// +build !ignore_autogenerated

// This file was autogenerated by deepcopy-gen. Do not edit it manually!

package v1

import (
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	intstr "k8s.io/apimachinery/pkg/util/intstr"
	unsafe "unsafe"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CustomDeploymentStrategyParams) DeepCopyInto(out *CustomDeploymentStrategyParams) {
	*out = *in
	if in.Environment != nil {
		in, out := &in.Environment, &out.Environment
		*out = make([]core_v1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Command != nil {
		in, out := &in.Command, &out.Command
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new CustomDeploymentStrategyParams.
func (in *CustomDeploymentStrategyParams) DeepCopy() *CustomDeploymentStrategyParams {
	if in == nil {
		return nil
	}
	out := new(CustomDeploymentStrategyParams)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentCause) DeepCopyInto(out *DeploymentCause) {
	*out = *in
	if in.ImageTrigger != nil {
		in, out := &in.ImageTrigger, &out.ImageTrigger
		if *in == nil {
			*out = nil
		} else {
			*out = new(DeploymentCauseImageTrigger)
			**out = **in
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentCause.
func (in *DeploymentCause) DeepCopy() *DeploymentCause {
	if in == nil {
		return nil
	}
	out := new(DeploymentCause)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentCauseImageTrigger) DeepCopyInto(out *DeploymentCauseImageTrigger) {
	*out = *in
	out.From = in.From
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentCauseImageTrigger.
func (in *DeploymentCauseImageTrigger) DeepCopy() *DeploymentCauseImageTrigger {
	if in == nil {
		return nil
	}
	out := new(DeploymentCauseImageTrigger)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentCondition) DeepCopyInto(out *DeploymentCondition) {
	*out = *in
	in.LastUpdateTime.DeepCopyInto(&out.LastUpdateTime)
	in.LastTransitionTime.DeepCopyInto(&out.LastTransitionTime)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentCondition.
func (in *DeploymentCondition) DeepCopy() *DeploymentCondition {
	if in == nil {
		return nil
	}
	out := new(DeploymentCondition)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentConditionType) DeepCopyInto(out *DeploymentConditionType) {
	{
		in := (*string)(unsafe.Pointer(in))
		out := (*string)(unsafe.Pointer(out))
		*out = *in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentConditionType.
func (in *DeploymentConditionType) DeepCopy() *DeploymentConditionType {
	if in == nil {
		return nil
	}
	out := new(DeploymentConditionType)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentConfig) DeepCopyInto(out *DeploymentConfig) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentConfig.
func (in *DeploymentConfig) DeepCopy() *DeploymentConfig {
	if in == nil {
		return nil
	}
	out := new(DeploymentConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DeploymentConfig) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentConfigList) DeepCopyInto(out *DeploymentConfigList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]DeploymentConfig, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentConfigList.
func (in *DeploymentConfigList) DeepCopy() *DeploymentConfigList {
	if in == nil {
		return nil
	}
	out := new(DeploymentConfigList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DeploymentConfigList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentConfigRollback) DeepCopyInto(out *DeploymentConfigRollback) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.UpdatedAnnotations != nil {
		in, out := &in.UpdatedAnnotations, &out.UpdatedAnnotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	out.Spec = in.Spec
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentConfigRollback.
func (in *DeploymentConfigRollback) DeepCopy() *DeploymentConfigRollback {
	if in == nil {
		return nil
	}
	out := new(DeploymentConfigRollback)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DeploymentConfigRollback) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentConfigRollbackSpec) DeepCopyInto(out *DeploymentConfigRollbackSpec) {
	*out = *in
	out.From = in.From
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentConfigRollbackSpec.
func (in *DeploymentConfigRollbackSpec) DeepCopy() *DeploymentConfigRollbackSpec {
	if in == nil {
		return nil
	}
	out := new(DeploymentConfigRollbackSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentConfigSpec) DeepCopyInto(out *DeploymentConfigSpec) {
	*out = *in
	in.Strategy.DeepCopyInto(&out.Strategy)
	if in.Triggers != nil {
		in, out := &in.Triggers, &out.Triggers
		*out = make(DeploymentTriggerPolicies, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.RevisionHistoryLimit != nil {
		in, out := &in.RevisionHistoryLimit, &out.RevisionHistoryLimit
		if *in == nil {
			*out = nil
		} else {
			*out = new(int32)
			**out = **in
		}
	}
	if in.Selector != nil {
		in, out := &in.Selector, &out.Selector
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Template != nil {
		in, out := &in.Template, &out.Template
		if *in == nil {
			*out = nil
		} else {
			*out = new(core_v1.PodTemplateSpec)
			(*in).DeepCopyInto(*out)
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentConfigSpec.
func (in *DeploymentConfigSpec) DeepCopy() *DeploymentConfigSpec {
	if in == nil {
		return nil
	}
	out := new(DeploymentConfigSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentConfigStatus) DeepCopyInto(out *DeploymentConfigStatus) {
	*out = *in
	if in.Details != nil {
		in, out := &in.Details, &out.Details
		if *in == nil {
			*out = nil
		} else {
			*out = new(DeploymentDetails)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.Conditions != nil {
		in, out := &in.Conditions, &out.Conditions
		*out = make([]DeploymentCondition, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentConfigStatus.
func (in *DeploymentConfigStatus) DeepCopy() *DeploymentConfigStatus {
	if in == nil {
		return nil
	}
	out := new(DeploymentConfigStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentDetails) DeepCopyInto(out *DeploymentDetails) {
	*out = *in
	if in.Causes != nil {
		in, out := &in.Causes, &out.Causes
		*out = make([]DeploymentCause, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentDetails.
func (in *DeploymentDetails) DeepCopy() *DeploymentDetails {
	if in == nil {
		return nil
	}
	out := new(DeploymentDetails)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentLog) DeepCopyInto(out *DeploymentLog) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentLog.
func (in *DeploymentLog) DeepCopy() *DeploymentLog {
	if in == nil {
		return nil
	}
	out := new(DeploymentLog)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DeploymentLog) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentLogOptions) DeepCopyInto(out *DeploymentLogOptions) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.SinceSeconds != nil {
		in, out := &in.SinceSeconds, &out.SinceSeconds
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	if in.SinceTime != nil {
		in, out := &in.SinceTime, &out.SinceTime
		if *in == nil {
			*out = nil
		} else {
			*out = new(meta_v1.Time)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.TailLines != nil {
		in, out := &in.TailLines, &out.TailLines
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	if in.LimitBytes != nil {
		in, out := &in.LimitBytes, &out.LimitBytes
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	if in.Version != nil {
		in, out := &in.Version, &out.Version
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentLogOptions.
func (in *DeploymentLogOptions) DeepCopy() *DeploymentLogOptions {
	if in == nil {
		return nil
	}
	out := new(DeploymentLogOptions)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DeploymentLogOptions) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentRequest) DeepCopyInto(out *DeploymentRequest) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	if in.ExcludeTriggers != nil {
		in, out := &in.ExcludeTriggers, &out.ExcludeTriggers
		*out = make([]DeploymentTriggerType, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentRequest.
func (in *DeploymentRequest) DeepCopy() *DeploymentRequest {
	if in == nil {
		return nil
	}
	out := new(DeploymentRequest)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *DeploymentRequest) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	} else {
		return nil
	}
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentStrategy) DeepCopyInto(out *DeploymentStrategy) {
	*out = *in
	if in.CustomParams != nil {
		in, out := &in.CustomParams, &out.CustomParams
		if *in == nil {
			*out = nil
		} else {
			*out = new(CustomDeploymentStrategyParams)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.RecreateParams != nil {
		in, out := &in.RecreateParams, &out.RecreateParams
		if *in == nil {
			*out = nil
		} else {
			*out = new(RecreateDeploymentStrategyParams)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.RollingParams != nil {
		in, out := &in.RollingParams, &out.RollingParams
		if *in == nil {
			*out = nil
		} else {
			*out = new(RollingDeploymentStrategyParams)
			(*in).DeepCopyInto(*out)
		}
	}
	in.Resources.DeepCopyInto(&out.Resources)
	if in.Labels != nil {
		in, out := &in.Labels, &out.Labels
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.Annotations != nil {
		in, out := &in.Annotations, &out.Annotations
		*out = make(map[string]string, len(*in))
		for key, val := range *in {
			(*out)[key] = val
		}
	}
	if in.ActiveDeadlineSeconds != nil {
		in, out := &in.ActiveDeadlineSeconds, &out.ActiveDeadlineSeconds
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentStrategy.
func (in *DeploymentStrategy) DeepCopy() *DeploymentStrategy {
	if in == nil {
		return nil
	}
	out := new(DeploymentStrategy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentStrategyType) DeepCopyInto(out *DeploymentStrategyType) {
	{
		in := (*string)(unsafe.Pointer(in))
		out := (*string)(unsafe.Pointer(out))
		*out = *in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentStrategyType.
func (in *DeploymentStrategyType) DeepCopy() *DeploymentStrategyType {
	if in == nil {
		return nil
	}
	out := new(DeploymentStrategyType)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentTriggerImageChangeParams) DeepCopyInto(out *DeploymentTriggerImageChangeParams) {
	*out = *in
	if in.ContainerNames != nil {
		in, out := &in.ContainerNames, &out.ContainerNames
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	out.From = in.From
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentTriggerImageChangeParams.
func (in *DeploymentTriggerImageChangeParams) DeepCopy() *DeploymentTriggerImageChangeParams {
	if in == nil {
		return nil
	}
	out := new(DeploymentTriggerImageChangeParams)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentTriggerPolicies) DeepCopyInto(out *DeploymentTriggerPolicies) {
	{
		in := (*[]DeploymentTriggerPolicy)(unsafe.Pointer(in))
		out := (*[]DeploymentTriggerPolicy)(unsafe.Pointer(out))
		*out = make([]DeploymentTriggerPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentTriggerPolicies.
func (in *DeploymentTriggerPolicies) DeepCopy() *DeploymentTriggerPolicies {
	if in == nil {
		return nil
	}
	out := new(DeploymentTriggerPolicies)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentTriggerPolicy) DeepCopyInto(out *DeploymentTriggerPolicy) {
	*out = *in
	if in.ImageChangeParams != nil {
		in, out := &in.ImageChangeParams, &out.ImageChangeParams
		if *in == nil {
			*out = nil
		} else {
			*out = new(DeploymentTriggerImageChangeParams)
			(*in).DeepCopyInto(*out)
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentTriggerPolicy.
func (in *DeploymentTriggerPolicy) DeepCopy() *DeploymentTriggerPolicy {
	if in == nil {
		return nil
	}
	out := new(DeploymentTriggerPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *DeploymentTriggerType) DeepCopyInto(out *DeploymentTriggerType) {
	{
		in := (*string)(unsafe.Pointer(in))
		out := (*string)(unsafe.Pointer(out))
		*out = *in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new DeploymentTriggerType.
func (in *DeploymentTriggerType) DeepCopy() *DeploymentTriggerType {
	if in == nil {
		return nil
	}
	out := new(DeploymentTriggerType)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ExecNewPodHook) DeepCopyInto(out *ExecNewPodHook) {
	*out = *in
	if in.Command != nil {
		in, out := &in.Command, &out.Command
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.Env != nil {
		in, out := &in.Env, &out.Env
		*out = make([]core_v1.EnvVar, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.Volumes != nil {
		in, out := &in.Volumes, &out.Volumes
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ExecNewPodHook.
func (in *ExecNewPodHook) DeepCopy() *ExecNewPodHook {
	if in == nil {
		return nil
	}
	out := new(ExecNewPodHook)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LifecycleHook) DeepCopyInto(out *LifecycleHook) {
	*out = *in
	if in.ExecNewPod != nil {
		in, out := &in.ExecNewPod, &out.ExecNewPod
		if *in == nil {
			*out = nil
		} else {
			*out = new(ExecNewPodHook)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.TagImages != nil {
		in, out := &in.TagImages, &out.TagImages
		*out = make([]TagImageHook, len(*in))
		copy(*out, *in)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LifecycleHook.
func (in *LifecycleHook) DeepCopy() *LifecycleHook {
	if in == nil {
		return nil
	}
	out := new(LifecycleHook)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *LifecycleHookFailurePolicy) DeepCopyInto(out *LifecycleHookFailurePolicy) {
	{
		in := (*string)(unsafe.Pointer(in))
		out := (*string)(unsafe.Pointer(out))
		*out = *in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new LifecycleHookFailurePolicy.
func (in *LifecycleHookFailurePolicy) DeepCopy() *LifecycleHookFailurePolicy {
	if in == nil {
		return nil
	}
	out := new(LifecycleHookFailurePolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RecreateDeploymentStrategyParams) DeepCopyInto(out *RecreateDeploymentStrategyParams) {
	*out = *in
	if in.TimeoutSeconds != nil {
		in, out := &in.TimeoutSeconds, &out.TimeoutSeconds
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	if in.Pre != nil {
		in, out := &in.Pre, &out.Pre
		if *in == nil {
			*out = nil
		} else {
			*out = new(LifecycleHook)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.Mid != nil {
		in, out := &in.Mid, &out.Mid
		if *in == nil {
			*out = nil
		} else {
			*out = new(LifecycleHook)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.Post != nil {
		in, out := &in.Post, &out.Post
		if *in == nil {
			*out = nil
		} else {
			*out = new(LifecycleHook)
			(*in).DeepCopyInto(*out)
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RecreateDeploymentStrategyParams.
func (in *RecreateDeploymentStrategyParams) DeepCopy() *RecreateDeploymentStrategyParams {
	if in == nil {
		return nil
	}
	out := new(RecreateDeploymentStrategyParams)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RollingDeploymentStrategyParams) DeepCopyInto(out *RollingDeploymentStrategyParams) {
	*out = *in
	if in.UpdatePeriodSeconds != nil {
		in, out := &in.UpdatePeriodSeconds, &out.UpdatePeriodSeconds
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	if in.IntervalSeconds != nil {
		in, out := &in.IntervalSeconds, &out.IntervalSeconds
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	if in.TimeoutSeconds != nil {
		in, out := &in.TimeoutSeconds, &out.TimeoutSeconds
		if *in == nil {
			*out = nil
		} else {
			*out = new(int64)
			**out = **in
		}
	}
	if in.MaxUnavailable != nil {
		in, out := &in.MaxUnavailable, &out.MaxUnavailable
		if *in == nil {
			*out = nil
		} else {
			*out = new(intstr.IntOrString)
			**out = **in
		}
	}
	if in.MaxSurge != nil {
		in, out := &in.MaxSurge, &out.MaxSurge
		if *in == nil {
			*out = nil
		} else {
			*out = new(intstr.IntOrString)
			**out = **in
		}
	}
	if in.Pre != nil {
		in, out := &in.Pre, &out.Pre
		if *in == nil {
			*out = nil
		} else {
			*out = new(LifecycleHook)
			(*in).DeepCopyInto(*out)
		}
	}
	if in.Post != nil {
		in, out := &in.Post, &out.Post
		if *in == nil {
			*out = nil
		} else {
			*out = new(LifecycleHook)
			(*in).DeepCopyInto(*out)
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new RollingDeploymentStrategyParams.
func (in *RollingDeploymentStrategyParams) DeepCopy() *RollingDeploymentStrategyParams {
	if in == nil {
		return nil
	}
	out := new(RollingDeploymentStrategyParams)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TagImageHook) DeepCopyInto(out *TagImageHook) {
	*out = *in
	out.To = in.To
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TagImageHook.
func (in *TagImageHook) DeepCopy() *TagImageHook {
	if in == nil {
		return nil
	}
	out := new(TagImageHook)
	in.DeepCopyInto(out)
	return out
}
