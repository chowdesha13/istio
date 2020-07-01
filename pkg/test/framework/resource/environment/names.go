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

package environment

const (
	// Kube environment name
	Kube Name = "kube"
)

// Name of environment
type Name string

// String implements fmt.Stringer
func (n Name) String() string {
	return string(n)
}

// environmentNames of supported environments
func Names() []Name {
	return []Name{
		Kube,
	}
}

// DefaultName is the name of the default environment
func DefaultName() Name {
	return Kube
}
