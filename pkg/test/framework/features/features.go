// Copyright 2020 Istio Authors
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

package features

import (
	"github.com/ghodss/yaml"
	"io/ioutil"
	"istio.io/pkg/log"
	"strings"
)

type Feature string

type Checker interface {
	Check(feature Feature) bool
}

type checkerImpl struct {
	m map[string]interface{}
}

func BuildChecker(yamlPath string) (Checker, error) {
	data, err := ioutil.ReadFile(yamlPath)
	if err != nil {
		log.Errorf("Error reading feature file: %s", yamlPath)
		return nil, err
	}
	m := make(map[string]interface{})

	err = yaml.Unmarshal(data, &m)
	if err != nil {
		log.Errorf("Error parsing features file: %s", err)
		return nil, err
	}
	return &checkerImpl{m}, nil
}

// returns true if the feature is defined in features.yaml,
// false if not
func (c *checkerImpl) Check(feature Feature) bool {
	return checkPathSegment(c.m, strings.Split(string(feature), "."))
}

func checkPathSegment(m map[string]interface{}, path []string) bool {
	segment := path[0]
	if val, ok := m[segment]; ok {
		if valmap, ok := val.(map[string]interface{}); ok {
			return checkPathSegment(valmap, path[1:])
		} else if val == nil {
			return true
		}
	}
	return false
}