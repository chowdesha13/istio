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

package handler

import (
	"testing"

	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/runtime2/testing/data"
	"istio.io/istio/mixer/pkg/runtime2/testing/util"
)

func TestEmptyConfig(t *testing.T) {
	adapters := data.BuildAdapters(nil)
	templates := data.BuildTemplates(nil)

	s := util.GetSnapshot(templates, adapters, data.ServiceConfig, data.GlobalConfig)

	table := Instantiate(Empty(), s, &data.FakeEnv{})
	h, found := table.GetHealthyHandler("h1.a1.istio-system")
	if !found {
		t.Fatal("not found")
	}

	if h == nil {
		t.Fatal("nil handler")
	}
}

func TestReuse(t *testing.T) {
	adapters := data.BuildAdapters(nil)
	templates := data.BuildTemplates(nil)

	s := util.GetSnapshot(templates, adapters, data.ServiceConfig, data.GlobalConfig)

	table := Instantiate(Empty(), s, &data.FakeEnv{})

	// Instantiate again using the same config, but add fault to the adapter to detect change.
	adapters = data.BuildAdapters(&adapter.Info{
		SupportedTemplates: []string{},
	})
	s = util.GetSnapshot(templates, adapters, data.ServiceConfig, data.GlobalConfig)

	table2 := Instantiate(table, s, &data.FakeEnv{})

	if len(table2.entries) != 1 {
		t.Fatal("size")
	}

	if table2.entries["h1.a1.istio-system"] != table.entries["h1.a1.istio-system"] {
		t.Fail()
	}
}

func TestNoReuse_DifferentConfig(t *testing.T) {
	adapters := data.BuildAdapters(nil)
	templates := data.BuildTemplates(nil)

	s := util.GetSnapshot(templates, adapters, data.ServiceConfig, data.GlobalConfig)

	table := Instantiate(Empty(), s, &data.FakeEnv{})

	// Instantiate again using the slightly different config
	s = util.GetSnapshot(templates, adapters, data.ServiceConfig, data.GlobalConfigI2)

	table2 := Instantiate(table, s, &data.FakeEnv{})

	if len(table2.entries) != 1 {
		t.Fatal("size")
	}

	if table2.entries["h1.a1.istio-system"] == table.entries["h1.a1.istio-system"] {
		t.Fail()
	}
}
