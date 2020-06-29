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

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	xdsapi "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	envoy_corev2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	envoy_corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang/protobuf/ptypes"
	structpb "github.com/golang/protobuf/ptypes/struct"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"istio.io/istio/istioctl/pkg/clioptions"
	"istio.io/istio/istioctl/pkg/multixds"
	"istio.io/istio/operator/cmd/mesh"
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pilot/pkg/xds"
	istioVersion "istio.io/pkg/version"
)

type sidecarSyncStatus struct {
	// nolint: structcheck, unused
	pilot string
	xds.SyncStatus
}

func newVersionCommand() *cobra.Command {
	profileCmd := mesh.ProfileCmd()
	var opts clioptions.ControlPlaneOptions
	versionCmd := istioVersion.CobraCommandWithOptions(istioVersion.CobraOptions{
		GetRemoteVersion: getRemoteInfoWrapper(&profileCmd, &opts),
		GetProxyVersions: getProxyInfoWrapper(&opts),
	})
	opts.AttachControlPlaneFlags(versionCmd)

	versionCmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "short" {
			err := flag.Value.Set("true")
			if err != nil {
				fmt.Fprintf(os.Stdout, "set flag %q as true failed due to error %v", flag.Name, err)
			}
		}
		if flag.Name == "remote" {
			err := flag.Value.Set("true")
			if err != nil {
				fmt.Fprintf(os.Stdout, "set flag %q as true failed due to error %v", flag.Name, err)
			}
		}
	})
	return versionCmd
}

func getRemoteInfo(opts clioptions.ControlPlaneOptions) (*istioVersion.MeshInfo, error) {
	kubeClient, err := kubeClientWithRevision(kubeconfig, configContext, opts.Revision)
	if err != nil {
		return nil, err
	}

	return kubeClient.GetIstioVersions(context.TODO(), istioNamespace)
}

func getRemoteInfoWrapper(pc **cobra.Command, opts *clioptions.ControlPlaneOptions) func() (*istioVersion.MeshInfo, error) {
	return func() (*istioVersion.MeshInfo, error) {
		remInfo, err := getRemoteInfo(*opts)
		if err != nil {
			fmt.Fprintf((*pc).OutOrStdout(), "%v\n", err)
			// Return nil so that the client version is printed
			return nil, nil
		}
		if remInfo == nil {
			fmt.Fprintf((*pc).OutOrStdout(), "Istio is not present in the cluster with namespace %q\n", istioNamespace)
		}
		return remInfo, err
	}
}

func getProxyInfoWrapper(opts *clioptions.ControlPlaneOptions) func() (*[]istioVersion.ProxyInfo, error) {
	return func() (*[]istioVersion.ProxyInfo, error) {
		return getProxyInfo(opts)
	}
}

func getProxyInfo(opts *clioptions.ControlPlaneOptions) (*[]istioVersion.ProxyInfo, error) {
	kubeClient, err := kubeClientWithRevision(kubeconfig, configContext, opts.Revision)
	if err != nil {
		return nil, err
	}

	// Ask Pilot for the Envoy sidecar sync status, which includes the sidecar version info
	allSyncz, err := kubeClient.AllDiscoveryDo(context.TODO(), istioNamespace, "/debug/syncz")
	if err != nil {
		return nil, err
	}

	pi := []istioVersion.ProxyInfo{}
	for _, syncz := range allSyncz {
		var sss []*sidecarSyncStatus
		err = json.Unmarshal(syncz, &sss)
		if err != nil {
			return nil, err
		}

		for _, ss := range sss {
			pi = append(pi, istioVersion.ProxyInfo{
				ID:           ss.ProxyID,
				IstioVersion: ss.SyncStatus.IstioVersion,
			})
		}
	}

	return &pi, nil
}

// xdsVersionCommand gets the Control Plane and Sidecar versions via XDS
func xdsVersionCommand() *cobra.Command {
	var opts clioptions.ControlPlaneOptions
	var centralOpts clioptions.CentralControlPlaneOptions
	var xdsResponses *xdsapi.DiscoveryResponse
	versionCmd := istioVersion.CobraCommandWithOptions(istioVersion.CobraOptions{
		GetRemoteVersion: xdsRemoteVersionWrapper(&opts, &centralOpts, &xdsResponses),
		GetProxyVersions: xdsProxyVersionWrapper(&xdsResponses),
	})
	opts.AttachControlPlaneFlags(versionCmd)
	centralOpts.AttachControlPlaneFlags(versionCmd)

	versionCmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Name == "short" {
			err := flag.Value.Set("true")
			if err != nil {
				fmt.Fprintf(os.Stdout, "set flag %q as true failed due to error %v", flag.Name, err)
			}
		}
		if flag.Name == "remote" {
			err := flag.Value.Set("true")
			if err != nil {
				fmt.Fprintf(os.Stdout, "set flag %q as true failed due to error %v", flag.Name, err)
			}
		}
	})
	return versionCmd
}

// xdsRemoteVersionWrapper uses outXDS to share the XDS response with xdsProxyVersionWrapper.
// (Screwy API on istioVersion.CobraCommandWithOptions)
// nolint: lll
func xdsRemoteVersionWrapper(opts *clioptions.ControlPlaneOptions, centralOpts *clioptions.CentralControlPlaneOptions, outXDS **xdsapi.DiscoveryResponse) func() (*istioVersion.MeshInfo, error) {
	return func() (*istioVersion.MeshInfo, error) {
		xdsRequest := xdsapi.DiscoveryRequest{
			Node: &envoy_corev2.Node{
				Id: "sidecar~0.0.0.0~debug~cluster.local",
			},
			TypeUrl: "istio.io/connections",
		}
		kubeClient, err := kubeClientWithRevision(kubeconfig, configContext, opts.Revision)
		if err != nil {
			return nil, err
		}
		xds, err := multixds.RequestAndProcessXds(&xdsRequest, centralOpts, istioNamespace, kubeClient)
		if err != nil {
			return nil, err
		}
		*outXDS = xds
		if xds.ControlPlane == nil {
			return &istioVersion.MeshInfo{
				istioVersion.ServerInfo{
					Component: "MISSING CP ID",
					Info: istioVersion.BuildInfo{
						Version: "MISSING CP ID",
					},
				},
			}, nil
		}
		cpID := map[string]interface{}{}
		err = json.Unmarshal([]byte(xds.ControlPlane.Identifier), &cpID)
		if err != nil {
			return nil, fmt.Errorf("could not parse CP Identifier: %w", err)
		}
		component, ok := cpID["component"].(string)
		if !ok {
			return nil, fmt.Errorf("could not parse CP ID component: %w", err)
		}
		cpInfo, ok := cpID["info"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("could not parse CP ID build info: %w", err)
		}
		strVersion, _ := cpInfo["version"].(string)
		buildStatus, _ := cpInfo["status"].(string)
		revision, _ := cpInfo["revision"].(string)
		tag, _ := cpInfo["tag"].(string)
		golangVersion, _ := cpInfo["golang_version"].(string)
		return &istioVersion.MeshInfo{
			istioVersion.ServerInfo{
				Component: component,
				Info: istioVersion.BuildInfo{
					Version:       strVersion,
					BuildStatus:   buildStatus,
					GitRevision:   revision,
					GitTag:        tag,
					GolangVersion: golangVersion,
				},
			},
		}, nil
	}
}

func xdsProxyVersionWrapper(xdsResponse **xdsapi.DiscoveryResponse) func() (*[]istioVersion.ProxyInfo, error) {
	return func() (*[]istioVersion.ProxyInfo, error) {
		pi := []istioVersion.ProxyInfo{}
		for _, resource := range (*xdsResponse).Resources {
			switch resource.TypeUrl {
			case "type.googleapis.com/envoy.config.core.v3.Node":
				node := envoy_corev3.Node{}
				err := ptypes.UnmarshalAny(resource, &node)
				if err != nil {
					return nil, fmt.Errorf("could not unmarshal Node: %w", err)
				}
				meta, err := model.ParseMetadata(node.Metadata)
				if err != nil || meta.ProxyConfig == nil {
					// Skip non-sidecars (e.g. istioctl queries)
					continue
				}
				pi = append(pi, istioVersion.ProxyInfo{
					ID:           node.Id,
					IstioVersion: getIstioVersionFromXdsMetadata(node.Metadata),
				})
			default:
				return nil, fmt.Errorf("unexpected resource type %q", resource.TypeUrl)
			}
		}
		return &pi, nil
	}
}

func getIstioVersionFromXdsMetadata(metadata *structpb.Struct) string {
	meta, err := model.ParseMetadata(metadata)
	if err != nil {
		return "unknown sidecar version"
	}
	return meta.IstioVersion
}
