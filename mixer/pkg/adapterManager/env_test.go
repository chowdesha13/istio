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

package adapterManager

import (
	"testing"
)

func TestEnv(t *testing.T) {
	// for now, just make sure nothing crashes...
	env := newEnv("Foo")
	log := env.Logger()
	log.Infof("Test%s", "ing")
	log.Warningf("Test%s", "ing")
	err := log.Errorf("Test%s", "ing")
	if err == nil {
		t.Error("Expected an error but got nil")
	}
}
