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

package factMapper

import (
	"errors"
	"strings"

	"github.com/istio/mixer/adapters"
)

type factMapperAdapter struct {
	// for each label, has an ordered slice of facts that can contribute to the label
	labelFacts map[string][]string

	// for each fact that matters, has a list of the labels to update if the fact changes
	factLabels map[string][]string
}

// NewFactMapperAdapter returns a new instances of a FactMapper adapter.
//
// The single argument specifies
// the set of label mapping rules. The keys of the map represent the
// name of labels, while the value specifies the mapping rules to
// turn individual fact values into label values.
//
// Mapping rules consist of a set of fact names separated by |. The
// label's value is derived by iterating through all the stated facts
// and picking the first one that is defined.
//
// TODO: need to ingest configuration state that defines the mapping rules
func NewFactMapperAdapter(labelRules map[string]string) (adapters.FactConversionAdapter, error) {
	// build our lookup tables
	labelFacts := make(map[string][]string)
	factLabels := make(map[string][]string)
	for label, rule := range labelRules {
		facts := strings.Split(rule, "|")

		// remove whitespace
		for i := range facts {
			facts[i] = strings.TrimSpace(facts[i])
			if facts[i] == "" {
				return nil, errors.New("can't have empty or whitespace fact in rule for label " + label)
			}
		}

		labelFacts[label] = facts

		for _, fact := range facts {
			factLabels[fact] = append(factLabels[fact], label)
		}
	}

	return &factMapperAdapter{
		labelFacts: labelFacts,
		factLabels: factLabels}, nil
}

func (f *factMapperAdapter) NewConverter() adapters.FactConverter {
	return newConverter(f.labelFacts, f.factLabels)
}
