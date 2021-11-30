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

package schema

import (
	_ "embed"
	"fmt"
)

//go:embed metadata.yaml
var metadata string

// get returns the contained resources.yaml file, in parsed form.
func get() (*Metadata, error) {
	m, err := ParseAndBuild(metadata)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// MustGet calls Get and panics if it returns and error.
func MustGet() *Metadata {
	s, err := get()
	if err != nil {
		panic(fmt.Sprintf("metadata.MustGet: %v", err))
	}
	return s
}
