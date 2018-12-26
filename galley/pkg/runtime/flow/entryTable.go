//  Copyright 2018 Istio Authors
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

package flow

import (
	"istio.io/istio/galley/pkg/runtime/resource"
)

// EntryTable is an efficient table for storing entries.
type EntryTable struct {
	generation int64
	resources  map[resource.FullName]resource.Entry
}

// Implement an optional Handler interface for the common use-case..
var _ Handler = &EntryTable{}

// NewEntryTable returns a new EntryTable
func NewEntryTable() *EntryTable {
	return &EntryTable{
		generation: 0,
		resources:  make(map[resource.FullName]resource.Entry),
	}
}

// Generation is a unique id that changes every time the table changes.
func (c *EntryTable) Generation() int64 {
	return c.generation
}

// Names returns the set of known names.
func (c *EntryTable) Names() []resource.FullName {
	result := make([]resource.FullName, 0, len(c.resources))
	for n := range c.resources {
		result = append(result, n)
	}
	return result
}

// Item returns the named item from the table
func (c *EntryTable) Item(name resource.FullName) resource.Entry {
	return c.resources[name]
}

// Set resource in the table. If this has caused table change (i.e. add or update w/ different version #)
// then it returns true
func (c *EntryTable) Set(entry resource.Entry) bool {
	previous, exists := c.resources[entry.ID.FullName]
	updated := !exists || previous.ID.Version != entry.ID.Version
	c.resources[entry.ID.FullName] = entry
	if updated {
		c.generation++
	}
	return updated
}

// Remove resource from the table. Returns true if the resource was actually removed.
func (c *EntryTable) Remove(key resource.FullName) bool {
	_, found := c.resources[key]
	delete(c.resources, key)
	if found {
		c.generation++
	}
	return found
}

// Count returns number of items in the table
func (c *EntryTable) Count() int {
	return len(c.resources)
}

// ForEachItem applies the given function to each item in the table
func (c *EntryTable) ForEachItem(fn func(e resource.Entry)) {
	for _, item := range c.resources {
		fn(item)
	}
}

// Handle implements Handler
func (a *EntryTable) Handle(ev resource.Event) bool {
	switch ev.Kind {
	case resource.Added, resource.Updated:
		return a.Set(ev.Entry)

	case resource.Deleted:
		return a.Remove(ev.Entry.ID.FullName)

	default:
		scope.Errorf("Unknown event kind encountered when processing %q: %v", ev.Entry.ID.String(), ev.Kind)
		return false
	}
}
