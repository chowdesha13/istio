// Copyright 2016 Google Inc.
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

package ipListChecker

import (
	"github.com/istio/mixer/adapters"
)

// InstanceConfig is used to configure instances.
type InstanceConfig struct {
	adapters.InstanceConfig

	// The URL where to find the list to check against
	ProviderURL string
}

type instance struct {
}

// newInstance returns a new instance of the adapter
func newInstance(config *InstanceConfig) (*instance, error) {
	return &instance{}, nil
}

func (inst *instance) Delete() {
}

func (inst *instance) CheckList(symbol string) bool {
	return false
}
