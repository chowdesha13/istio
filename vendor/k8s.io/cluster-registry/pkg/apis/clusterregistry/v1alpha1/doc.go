/*
Copyright 2017 The Kubernetes Authors.

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

// Package v1alpha1 is the v1alpha1 version of the clusterregistry API, whose
// internal version is defined in
// k8s.io/cluster-registry/pkg/apis/clusterregistry.
//
// +k8s:conversion-gen=k8s.io/cluster-registry/pkg/apis/clusterregistry
// +k8s:deepcopy-gen=package,register
// +k8s:openapi-gen=true
// +groupName=clusterregistry.k8s.io
package v1alpha1 // import "k8s.io/cluster-registry/pkg/apis/clusterregistry/v1alpha1"
