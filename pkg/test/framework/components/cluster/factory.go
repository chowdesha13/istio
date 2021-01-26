//  Copyright Istio Authors
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package cluster

import (
	"istio.io/istio/pkg/test/framework/resource"
	"istio.io/istio/pkg/test/scopes"
)

type Kind string

const (
	Kubernetes Kind = "Kubernetes"
	Fake       Kind = "Fake"
	Aggregate  Kind = "Aggregate"
	StaticVM   Kind = "StaticVM"
	Unknown    Kind = "Unknown"
)

type Factory interface {
	Kind() Kind
	With(config ...Config) Factory
	Build(Map) (resource.Clusters, error)
}

type Config struct {
	Kind               Kind       `yaml:"kind,omitempty"`
	Name               string     `yaml:"clusterName,omitempty"`
	Network            string     `yaml:"network,omitempty"`
	PrimaryClusterName string     `yaml:"primaryClusterName,omitempty"`
	ConfigClusterName  string     `yaml:"configClusterName,omitempty"`
	Meta               ConfigMeta `yaml:"meta,omitempty"`
}

type ConfigMeta map[string]interface{}

func (m ConfigMeta) String(key string) string {
	v, ok := m[key].(string)
	if !ok {
		return ""
	}
	return v
}

func (m ConfigMeta) Slice(key string) []ConfigMeta {
	v, ok := m[key].([]ConfigMeta)
	if !ok {
		scopes.Framework.Warnf("failed to parse key %q as config slice, defaulting to empty", key)
		return nil
	}
	return v
}

func (m ConfigMeta) Bool(key string) bool {
	v, ok := m[key].(bool)
	if !ok {
		scopes.Framework.Warnf("failed to parse key %q as bool, defaulting to false", key)
		return false
	}
	return v
}

func (m ConfigMeta) Int(key string) int {
	v, ok := m[key].(int)
	if !ok {
		scopes.Framework.Warnf("failed to parse key %q as int, defaulting to 0", key)
		return 0
	}
	return v
}
