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

package genericListChecker

import (
	"istio.io/mixer/pkg/adapter"
)

// AspectConfig is used to configure an adapter.
type AspectConfig struct {
	adapter.AspectConfig

	// The set of entries in the list to check against. This overrides any adapter-level
	// entries. If this is not supplied, then the adapter's list is used instead.
	ListEntries []string
}

type aspectState struct {
	entries       map[string]string
	whitelistMode bool
}

// newAspect returns a new aspect.
func newAspect(config *AspectConfig, entries map[string]string, whitelistMode bool) (adapter.ListChecker, error) {
	if config.ListEntries != nil {
		// override the adapter-level entries
		entries = make(map[string]string, len(config.ListEntries))
		for _, entry := range config.ListEntries {
			entries[entry] = entry
		}
	}

	return &aspectState{entries: entries, whitelistMode: whitelistMode}, nil
}

func (a *aspectState) Close() error {
	a.entries = nil
	return nil
}

func (a *aspectState) CheckList(symbol string) (bool, error) {
	_, ok := a.entries[symbol]
	if a.whitelistMode {
		return ok, nil
	}
	return !ok, nil
}
