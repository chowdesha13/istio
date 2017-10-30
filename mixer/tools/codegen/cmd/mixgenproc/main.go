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

	interfacegen "istio.io/istio/mixer/tools/codegen/pkg/interfacegen"
)

func withArgs(args []string, errorf func(format string, a ...interface{})) {
	var outInterfaceFile string
	var oAugmentedTmplFile string
	var mappings []string

	rootCmd := cobra.Command{
		Use: "mixgenproc <file descriptor set protobuf>",
		Short: "Parses a [Template](http://TODO) and generates Go interfaces for adapters to implement. " +
			"Also generates an augmented template proto that contains the Type and InstanceParam messages.",
		Long: "If an adapter wants to process a particular [Template](http://TODO), it must implement the Go interface " +
			"generated by this tool.\n" +
			"The input <file descriptor set protobuf> must contain a proto file that defines the template.\n" +
			"Example: mixgenproc metricTemplateFileDescriptorSet.pb -o MetricProcessor.go -t MetricProcessor.revised.proto",
		Run: func(cmd *cobra.Command, args []string) {

			if len(args) == 0 {
				errorf("Must specify a file descriptor set protobuf file.")
			}
			if len(args) != 1 {
				errorf("Only one input file is allowed.")
			}
			var err error

			outInterfaceFile, err = filepath.Abs(outInterfaceFile)
			if err != nil {
				errorf("Invalid path %s: %v", outInterfaceFile, err)
			}
			oAugmentedTmplFile, err = filepath.Abs(oAugmentedTmplFile)
			if err != nil {
				errorf("Invalid path %s: %v", oAugmentedTmplFile, err)
			}
			importMapping := make(map[string]string)
			for _, maps := range mappings {
				m := strings.Split(maps, ":")
				importMapping[strings.TrimSpace(m[0])] = strings.TrimSpace(m[1])
			}

			generator := interfacegen.Generator{OutInterfacePath: outInterfaceFile, OAugmentedTmplPath: oAugmentedTmplFile, ImptMap: importMapping}
			if err := generator.Generate(args[0]); err != nil {
				errorf("%v", err)
			}
		},
	}

	rootCmd.SetArgs(args)
	rootCmd.PersistentFlags().StringVarP(&outInterfaceFile, "output", "o", "./generated.go", "Output "+
		"path for generated Go source file. If an adapter wants to process a particular [Template](http://TODO), "+
		"it must implement the Go interface generated in this file.")

	rootCmd.PersistentFlags().StringVarP(&oAugmentedTmplFile, "output_template", "t", "./generated_template.proto", "Output "+
		"path for augmented template file.")

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
			fmt.Fprintf(os.Stderr, format+"\n", a...) // nolint: gas
			os.Exit(1)
		})
}
