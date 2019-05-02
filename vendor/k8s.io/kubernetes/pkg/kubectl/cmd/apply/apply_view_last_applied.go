/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apply

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/genericclioptions/resource"
	"k8s.io/kubernetes/pkg/kubectl"
	cmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/util/i18n"
	"k8s.io/kubernetes/pkg/kubectl/util/templates"
	"sigs.k8s.io/yaml"
)

type ViewLastAppliedOptions struct {
	FilenameOptions              resource.FilenameOptions
	Selector                     string
	LastAppliedConfigurationList []string
	OutputFormat                 string
	All                          bool
	Factory                      cmdutil.Factory

	genericclioptions.IOStreams
}

var (
	applyViewLastAppliedLong = templates.LongDesc(i18n.T(`
		View the latest last-applied-configuration annotations by type/name or file.

		The default output will be printed to stdout in YAML format. One can use -o option
		to change output format.`))

	applyViewLastAppliedExample = templates.Examples(i18n.T(`
		# View the last-applied-configuration annotations by type/name in YAML.
		kubectl apply view-last-applied deployment/nginx

		# View the last-applied-configuration annotations by file in JSON
		kubectl apply view-last-applied -f deploy.yaml -o json`))
)

func NewViewLastAppliedOptions(ioStreams genericclioptions.IOStreams) *ViewLastAppliedOptions {
	return &ViewLastAppliedOptions{
		OutputFormat: "yaml",

		IOStreams: ioStreams,
	}
}

func NewCmdApplyViewLastApplied(f cmdutil.Factory, ioStreams genericclioptions.IOStreams) *cobra.Command {
	options := NewViewLastAppliedOptions(ioStreams)

	cmd := &cobra.Command{
		Use:                   "view-last-applied (TYPE [NAME | -l label] | TYPE/NAME | -f FILENAME)",
		DisableFlagsInUseLine: true,
		Short:                 i18n.T("View latest last-applied-configuration annotations of a resource/object"),
		Long:                  applyViewLastAppliedLong,
		Example:               applyViewLastAppliedExample,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.CheckErr(options.Complete(cmd, f, args))
			cmdutil.CheckErr(options.Validate(cmd))
			cmdutil.CheckErr(options.RunApplyViewLastApplied(cmd))
		},
	}

	cmd.Flags().StringVarP(&options.OutputFormat, "output", "o", options.OutputFormat, "Output format. Must be one of yaml|json")
	cmd.Flags().StringVarP(&options.Selector, "selector", "l", options.Selector, "Selector (label query) to filter on, supports '=', '==', and '!='.(e.g. -l key1=value1,key2=value2)")
	cmd.Flags().BoolVar(&options.All, "all", options.All, "Select all resources in the namespace of the specified resource types")
	usage := "that contains the last-applied-configuration annotations"
	cmdutil.AddFilenameOptionFlags(cmd, &options.FilenameOptions, usage)

	return cmd
}

func (o *ViewLastAppliedOptions) Complete(cmd *cobra.Command, f cmdutil.Factory, args []string) error {
	cmdNamespace, enforceNamespace, err := f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	r := f.NewBuilder().
		Unstructured().
		NamespaceParam(cmdNamespace).DefaultNamespace().
		FilenameParam(enforceNamespace, &o.FilenameOptions).
		ResourceTypeOrNameArgs(enforceNamespace, args...).
		SelectAllParam(o.All).
		LabelSelectorParam(o.Selector).
		Latest().
		Flatten().
		Do()
	err = r.Err()
	if err != nil {
		return err
	}

	err = r.Visit(func(info *resource.Info, err error) error {
		if err != nil {
			return err
		}

		configString, err := kubectl.GetOriginalConfiguration(info.Object)
		if err != nil {
			return err
		}
		if configString == nil {
			return cmdutil.AddSourceToErr(fmt.Sprintf("no last-applied-configuration annotation found on resource: %s\n", info.Name), info.Source, err)
		}
		o.LastAppliedConfigurationList = append(o.LastAppliedConfigurationList, string(configString))
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

func (o *ViewLastAppliedOptions) Validate(cmd *cobra.Command) error {
	return nil
}

func (o *ViewLastAppliedOptions) RunApplyViewLastApplied(cmd *cobra.Command) error {
	for _, str := range o.LastAppliedConfigurationList {
		switch o.OutputFormat {
		case "json":
			jsonBuffer := &bytes.Buffer{}
			err := json.Indent(jsonBuffer, []byte(str), "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprint(o.Out, string(jsonBuffer.Bytes()))
		case "yaml":
			yamlOutput, err := yaml.JSONToYAML([]byte(str))
			if err != nil {
				return err
			}
			fmt.Fprint(o.Out, string(yamlOutput))
		default:
			return cmdutil.UsageErrorf(
				cmd,
				"Unexpected -o output mode: %s, the flag 'output' must be one of yaml|json",
				o.OutputFormat)
		}
	}

	return nil
}
