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

package mesh

import (
	"fmt"

	"github.com/spf13/cobra"

	"istio.io/istio/operator/pkg/util/clog"
)

type operatorDumpArgs struct {
	// common is shared operator args
	common operatorCommonArgs
}

func addOperatorDumpFlags(cmd *cobra.Command, args *operatorDumpArgs) {
	addOperatorCommonFlags(cmd, &args.common)

	cmd.PersistentFlags().StringVarP(&args.common.outputFormat, "output", "o", yamlOutput,
		"Output format: one of json|yaml")
}

func operatorDumpCmd(rootArgs *rootArgs, odArgs *operatorDumpArgs) *cobra.Command {
	return &cobra.Command{
		Use:   "dump",
		Short: "Dumps the Istio operator controller manifest.",
		Long:  "The dump subcommand dumps the Istio operator controller manifest.",
		Args:  cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			l := clog.NewConsoleLogger(cmd.OutOrStdout(), cmd.ErrOrStderr(), installerScope)
			operatorDump(rootArgs, odArgs, l)
		},
	}
}

// operatorDump dumps the manifest used to install the operator.
func operatorDump(args *rootArgs, odArgs *operatorDumpArgs, l clog.Logger) {
	if err := validateOperatorOutputFormatFlag(odArgs.common.outputFormat); err != nil {
		l.LogAndFatal(fmt.Errorf("unknown output format: %v", odArgs.common.outputFormat))
	}

	_, mstr, err := renderOperatorManifest(args, &odArgs.common)
	if err != nil {
		l.LogAndFatal(err)
	}

	var output string
	if output, err = yamlToFormat(mstr, odArgs.common.outputFormat); err != nil {
		l.LogAndFatal(err)
	}
	l.Print(output)
}

// validateOutputFormatFlag validates if the output format is valid.
func validateOperatorOutputFormatFlag(outputFormat string) error {
	switch outputFormat {
	case jsonOutput, yamlOutput:
	default:
		return fmt.Errorf("unknown output format: %s", outputFormat)
	}
	return nil
}
