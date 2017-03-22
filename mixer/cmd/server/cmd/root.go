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

package cmd

import (
	"flag"
	"fmt"

	"github.com/spf13/cobra"

	// need to pull this in
	_ "google.golang.org/grpc/grpclog/glogger"
)

// A function used for normal output.
type outFn func(format string, a ...interface{})

// A function used for error output.
type errorFn func(format string, a ...interface{})

// GetRootCmd returns the root of the cobra command-tree.
func GetRootCmd(args []string, outf outFn, errorf errorFn) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "mixs",
		Short: "The Istio mixer provides control plane functionality to the Istio proxy and services",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("'%s' is an invalid argument", args[0])
			}
			return nil
		},
	}
	rootCmd.SetArgs(args)
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)

	// hack to make flag.Parsed return true such that glog is happy
	// about the flags having been parsed
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	/* #nosec */
	_ = fs.Parse([]string{})
	flag.CommandLine = fs

	rootCmd.AddCommand(adapterCmd(outf))
	rootCmd.AddCommand(serverCmd(outf, errorf))

	return rootCmd
}
