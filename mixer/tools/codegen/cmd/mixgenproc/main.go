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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	interfacegen "istio.io/mixer/tools/codegen/pkg/interfacegen"
)

func withArgs(args []string, errorf func(format string, a ...interface{})) {
	var outFilePath string
	var mappings []string

	rootCmd := cobra.Command{
		Use:   "mixgenproc <File descriptor set protobuf>",
		Short: "Parses a [Template](http://TODO) and generates Go interfaces for adapters to implement.",
		Long: "If an adapter wants to process a particular [Template](http://TODO), it must implement the Go interface " +
			"generated by this tool.\n" +
			"The input <File descriptor set protobuf> must contain a proto file that defines the template.\n" +
			"Example: mixgenproc metricTemplateFileDescriptorSet.pb -o MetricProcessor.go",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				errorf("Must specify a file descriptor set protobuf file.")
			}
			if len(args) != 1 {
				errorf("Only one input file is allowed.")
			}
			outFileFullPath, err := filepath.Abs(outFilePath)
			if err != nil {
				errorf("Invalid path %s. %v", outFilePath, err)
			}
			importMapping := make(map[string]string)
			for _, maps := range mappings {
				m := strings.Split(maps, ":")
				importMapping[m[0]] = m[1]
			}
			generator := interfacegen.Generator{OutFilePath: outFileFullPath, ImportMapping: importMapping}
			if err := generator.Generate(args[0]); err != nil {
				errorf("%v", err)
			}
		},
	}

	rootCmd.SetArgs(args)
	rootCmd.PersistentFlags().StringVarP(&outFilePath, "output", "o", "./generated.go", "Output "+
		"path for generated Go source file.")

	rootCmd.PersistentFlags().StringArrayVarP(&mappings, "importmapping",
		"m", []string{},
		"colon separated mapping of proto import to Go package names."+
			" -m google/protobuf/descriptor.proto:github.com/golang/protobuf/protoc-gen-go/descriptor")

	if err := rootCmd.Execute(); err != nil {
		errorf("%v", err)
	}
}

func main() {
	withArgs(os.Args[1:],
		func(format string, a ...interface{}) {
			fmt.Fprintf(os.Stderr, format+"\n", a...)
			os.Exit(1)
		})
}
