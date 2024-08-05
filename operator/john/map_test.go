package john

import (
	"istio.io/istio/pkg/test/util/assert"
	"testing"
)

func TestMakePatch(t *testing.T) {
	data := map[string]string{"hello": "world"}
	cases := []struct {
		name   string
		inPath string
		inData any
		out    string
	}{
		{
			name:   "simple",
			inPath: "spec",
			inData: data,
			out:    "",
		},
		{
			name:   "array",
			inPath: "top.[0]",
			inData: data,
			out:    "",
		},
		{
			name:   "kv",
			inPath: "env.[name:POD_NAME].value",
			inData: data,
			out:    "",
		},
		{
			name:   "escape kv",
			inPath: "env.[name:foo\\.bar].value",
			inData: "hi",
			out:    `{"env":[{"name":"foo\\.bar","value":"hi"}]}`,
		},
		{
			name:   "delete kv last",
			inPath: "env.[name:POD_NAME]",
			inData: nil,
			out:    `{"env":[{"$patch":"delete","name":"POD_NAME"}]}`,
		},
		{
			name:   "set kv primitive",
			inPath: "spec.ports.[name:https-dns].port",
			inData: 11111,
			out:    `{"spec":{"ports":[{"name":"https-dns","port":11111}]}}`,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			out := MakePatch(tt.inData, tt.inPath)
			assert.Equal(t, tt.out, out)
		})
	}
}

func TestSetPath(t *testing.T) {
	fromJson := func(s string) Map {
		m, err := FromJson[Map]([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct {
		name   string
		base   Map
		inPath string
		inData any
		out    string
	}{
		{
			name:   "trivial",
			inPath: "spec",
			inData: 1,
			out:    `{"spec":1}`,
		},
		{
			name:   "simple create",
			inPath: "spec.bar",
			inData: 1,
			out:    `{"spec":{"bar":1}}`,
		},
		{
			name:   "simple merge",
			inPath: "spec.bar",
			base:   Map{"spec": Map{"foo": "baz"}},
			inData: 1,
			out:    `{"spec":{"bar":1,"foo":"baz"}}`,
		},
		{
			name:   "array",
			inPath: "top.[0]",
			inData: 1,
			out:    `{"top":[1]}`,
		},
		{
			name:   "array and values",
			inPath: "top.[0].bar",
			inData: 1,
			out:    `{"top":[{"bar":1}]}`,
		},
		{
			name:   "array and values merge",
			inPath: "top.[0].bar",
			base:   fromJson(`{"top":[{"baz":2}]}`),
			inData: 1,
			out:    `{"top":[{"bar":1,"baz":2}]}`,
		},
		{
			name:   "kv set",
			inPath: "env.[name:POD_NAME].value",
			base: fromJson(`{"env":[{"name":"POD_NAME"}]}`),
			inData: 1,
			out:    `{"env":[{"name":"POD_NAME","value":1}]}`,
		},
		{
			name:   "escape kv",
			inPath: "env.[name:foo\\.bar].value",
			base: fromJson(`{"env":[{"name":"foo\\.bar"}]}`),
			inData: "hi",
			out:    `{"env":[{"name":"foo\\.bar","value":"hi"}]}`,
		},
		{
			name:   "set kv",
			inPath: "spec.ports.[name:https-dns].port",
			base: fromJson(`{"spec":{"ports":[{"name":"https-dns"}]}}`),
			inData: 11111,
			out:    `{"spec":{"ports":[{"name":"https-dns","port":11111}]}}`,
		},
		{
			name:   "set unmatched kv",
			inPath: "spec.ports.[name:https-dns].port",
			inData: 11111,
			out:    ``,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m := Map{}
			if tt.base != nil {
				m = tt.base
			}
			err := m.SetPath(tt.inPath, tt.inData)
			if tt.out != "" {
				assert.NoError(t, err)
				assert.Equal(t, tt.out, m.JSON())
			} else {
				assert.Error(t, err)
			}
		})
	}
}
