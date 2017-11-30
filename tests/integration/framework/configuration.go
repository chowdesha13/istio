// Copyright 2017 Istio Authors
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

package framework

// Config is interface to extend the ability of the framework.
// Any item (component, environment or even framework itself can has a Config)
// Actual implement can take this interface with its configuration.
// Implement is recommended to also take sync.Mutex to lock data while read/write
type Config interface {
	// GetConfig return the Config.
	GetConfig() *Config

	// SetConfig set a Config interface to an item.
	SetConfig(config *Config)
}
