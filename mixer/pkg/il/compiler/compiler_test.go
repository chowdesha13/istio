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

package compiler

import (
	"fmt"
	"strings"
	"testing"

	"istio.io/istio/mixer/pkg/config/descriptor"
	"istio.io/istio/mixer/pkg/expr"
	"istio.io/istio/mixer/pkg/il/interpreter"
	"istio.io/istio/mixer/pkg/il/runtime"
	ilt "istio.io/istio/mixer/pkg/il/testing"
	"istio.io/istio/mixer/pkg/il/text"
)

func TestCompile(t *testing.T) {

	for i, test := range ilt.TestData {
		// If there is no expression in the test, skip it. It is most likely an interpreter test that directly runs
		// off IL.
		if test.E == "" {
			continue
		}

		name := fmt.Sprintf("%d '%s'", i, test.TestName())
		t.Run(name, func(tt *testing.T) {

			finder := descriptor.NewFinder(test.Conf())

			fns := runtime.ExternFunctionMetadata
			if test.Fns != nil {
				fns = append(fns, test.Fns...)
			}
			result, err := Compile(test.E, finder, expr.FuncMap(fns))
			if err != nil {
				if err.Error() != test.CompileErr {
					tt.Fatalf("Unexpected error: '%s' != '%s'", err.Error(), test.CompileErr)
				}
				return
			}

			if test.CompileErr != "" {
				tt.Fatalf("expected error not found: '%s'", test.CompileErr)
				return
			}

			if test.IL != "" {
				actual := text.WriteText(result.Program)
				if strings.TrimSpace(actual) != strings.TrimSpace(test.IL) {
					tt.Log("===== EXPECTED ====\n")
					tt.Log(test.IL)
					tt.Log("\n====== ACTUAL =====\n")
					tt.Log(actual)
					tt.Log("===================\n")
					tt.Fail()
					return
				}
			}

			input := test.I
			if input == nil {
				input = map[string]interface{}{}
			}
			b := ilt.NewFakeBag(input)

			externs := make(map[string]interpreter.Extern)
			for k, v := range runtime.Externs {
				externs[k] = v
			}
			if test.Externs != nil {
				for k, v := range test.Externs {
					externs[k] = interpreter.ExternFromFn(k, v)
				}
			}

			i := interpreter.New(result.Program, externs)
			v, err := i.Eval("eval", b)
			if err != nil {
				if test.Err != err.Error() {
					tt.Fatalf("expected error not found: E:'%v', A:'%v'", test.Err, err)
				}
				return
			}
			if test.Err != "" {
				tt.Fatalf("expected error not received: '%v'", test.Err)
			}

			if !ilt.AreEqual(test.R, v.AsInterface()) {
				tt.Fatalf("Result match failed: %+v == %+v", test.R, v.AsInterface())
			}
		})
	}
}
