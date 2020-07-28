// Copyright Istio Authors.
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
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/golang/protobuf/jsonpb"
	"github.com/spf13/cobra"

	containerpb "google.golang.org/genproto/googleapis/container/v1"

	meshconfig "istio.io/api/mesh/v1alpha1"
	networkingv1alpha3 "istio.io/api/networking/v1alpha3"
	clientv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	"istio.io/istio/pkg/config/schema/collections"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var (
	name           string
	network        string
	serviceAccount string
	filename       string
	outputName     string
	ports          []string

	// optional GKE flags
	gkeProject      string
	clusterLocation string
)

const (
	tempPerms = os.FileMode(0644)
)

func sidecarCommands() *cobra.Command {
	sidecarCmd := &cobra.Command{
		Use:   "sidecar",
		Short: "Commands to assist in managing sidecar configuration",
	}
	sidecarCmd.AddCommand(createGroupCommand())
	sidecarCmd.AddCommand(generateConfigCommand())
	return sidecarCmd
}

func createGroupCommand() *cobra.Command {
	createGroupCmd := &cobra.Command{
		Use:   "create-group",
		Short: "Creates a WorkloadGroup YAML artifact representing workload instances",
		Long: `Creates a WorkloadGroup YAML artifact representing workload instances for passing to the Kubernetes API server.
The generated artifact can be applied by running kubectl apply -f workloadgroup.yaml.`,
		Example: "create-group --name foo --namespace bar --labels app=foo,bar=baz --ports grpc=3550,http=8080 --network local --serviceAccount sa",
		Args: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("expecting a service name")
			}
			if namespace == "" {
				return fmt.Errorf("expecting a service namespace")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			u := &unstructured.Unstructured{
				Object: map[string]interface{}{
					"apiVersion": collections.IstioNetworkingV1Alpha3Workloadgroups.Resource().APIVersion(),
					"kind":       collections.IstioNetworkingV1Alpha3Workloadgroups.Resource().Kind(),
					"metadata": map[string]interface{}{
						"name":      name,
						"namespace": namespace,
					},
				},
			}
			spec := &networkingv1alpha3.WorkloadGroup{
				Labels:         convertToStringMap(labels),
				Ports:          convertToUnsignedInt32Map(ports),
				Network:        network,
				ServiceAccount: serviceAccount,
			}
			wgYAML, err := generateWorkloadGroupYAML(u, spec)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(wgYAML)
			return err
		},
	}
	createGroupCmd.PersistentFlags().StringVar(&name, "name", "", "The name of the workload group")
	createGroupCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "", "The namespace that the workload instances will belong to")
	createGroupCmd.PersistentFlags().StringSliceVarP(&labels, "labels", "l", nil, "The labels to apply to the workload instances; e.g. -l env=prod,vers=2")
	createGroupCmd.PersistentFlags().StringSliceVarP(&ports, "ports", "p", nil, "The incoming ports that the workload instances will expose")
	createGroupCmd.PersistentFlags().StringVar(&network, "network", "default", "The name of the network for the workload instances")
	createGroupCmd.PersistentFlags().StringVarP(&serviceAccount, "serviceAccount", "s", "default", "The service identity to associate with the workload instances")
	return createGroupCmd
}

func generateWorkloadGroupYAML(u *unstructured.Unstructured, spec *networkingv1alpha3.WorkloadGroup) ([]byte, error) {
	iSpec, err := unstructureIstioType(spec)
	if err != nil {
		return nil, err
	}
	u.Object["spec"] = iSpec

	wgYAML, err := yaml.Marshal(u.Object)
	if err != nil {
		return nil, err
	}
	return wgYAML, nil
}

// Cluster inference from the current kubectl context only works for GKE
func generateConfigCommand() *cobra.Command {
	generateConfigCmd := &cobra.Command{
		Use:   "generate-config",
		Short: "Generates and packs all the required configuration files for deployment",
		Long: `Takes in WorkloadGroup artifact, then generates and packs all the required configuration files for deployment. 
This includes a MeshConfig resource, the cluster.env file, and necessary certificates and security tokens. 
Tries to automatically infer the target cluster, and prompts for flags if the cluster cannot be inferred`,
		Example: "generate-config -f workloadgroup.yaml -o config",
		Args: func(cmd *cobra.Command, args []string) error {
			if filename == "" {
				return fmt.Errorf("expecting a WorkloadGroup artifact file")
			}
			if outputName == "" {
				return fmt.Errorf("expecting an output filename")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			wg := &clientv1alpha3.WorkloadGroup{}
			if err := readWorkloadGroup(filename, wg); err != nil {
				return err
			}
			// consider passed in flags before attempting to infer config
			cluster, err := gkeCluster(gkeProject, clusterLocation, clusterName)
			if err != nil {
				gkeProject, clusterLocation, clusterName, cluster, err = gkeConfig()
				if err != nil {
					return fmt.Errorf("could not infer (project, location, cluster). Try passing in flags instead")
				}
			}

			if err = createConfig(wg, cluster, outputName); err != nil {
				return err
			}
			fmt.Printf("generated config for (%s, %s, %s)\n", gkeProject, clusterLocation, clusterName)
			return nil
		},
	}
	generateConfigCmd.PersistentFlags().StringVarP(&filename, "file", "f", "", "filename of the WorkloadGroup artifact")
	generateConfigCmd.PersistentFlags().StringVarP(&outputName, "output", "o", "", "Name of the tarball to be created")

	generateConfigCmd.PersistentFlags().StringVar(&gkeProject, "project", "", "Target project name")
	generateConfigCmd.PersistentFlags().StringVar(&clusterLocation, "location", "", "Target cluster location")
	generateConfigCmd.PersistentFlags().StringVar(&clusterName, "cluster", "", "Target cluster name")
	return generateConfigCmd
}

func readWorkloadGroup(filename string, wg *clientv1alpha3.WorkloadGroup) error {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(f, wg); err != nil {
		return err
	}
	return nil
}

// Creates all the relevant config for the given workload group and cluster
func createConfig(wg *clientv1alpha3.WorkloadGroup, cluster *containerpb.Cluster, outputName string) error {
	temp, err := ioutil.TempDir("./", outputName)
	if err != nil {
		return err
	}
	// TODO: pack temp into a tarball and then delete folder
	// defer os.RemoveAll(temp)

	if err = createClusterEnv(wg, cluster, temp); err != nil {
		return err
	}
	if err = createHosts(temp); err != nil {
		return err
	}
	if err = createCertificates(temp); err != nil {
		return err
	}
	if err = createMeshConfig(wg, cluster, temp); err != nil {
		return err
	}
	if err = Tar(temp, outputName); err != nil {
		return err
	}
	return nil
}

// Write cluster.env into the given directory
func createClusterEnv(wg *clientv1alpha3.WorkloadGroup, cluster *containerpb.Cluster, dir string) error {
	for _, v := range wg.Spec.Ports {
		ports = append(ports, fmt.Sprint(v))
	}
	// default attributes and service name, namespace, ports, service account, service CIDR
	clusterEnv := map[string]string{
		"ISTIO_CP_AUTH":       "MUTUAL_TLS",
		"ISTIO_INBOUND_PORTS": strings.Join(ports, ","),
		"ISTIO_NAMESPACE":     wg.Namespace,
		"ISTIO_PILOT_PORT":    "15012",
		"ISTIO_SERVICE":       fmt.Sprintf("%s.%s", wg.Name, wg.Namespace),
		"ISTIO_SERVICE_CIDR":  cluster.ServicesIpv4Cidr,
		"SERVICE_ACCOUNT":     wg.Spec.ServiceAccount,
	}
	return ioutil.WriteFile(dir+"/cluster.env", []byte(mapToString(clusterEnv)), tempPerms)
}

// Create the needed hosts addition in the given directory
func createHosts(dir string) error {
	istiod, err := k8sService("istiod", "istio-system")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dir+"/hosts", []byte(fmt.Sprintf("%s\t%s", istiod.Spec.ClusterIP, "istiod.istio-system.svc")), tempPerms)
}

// Get and store the needed certificates
// TODO: user internal generate-cert
func createCertificates(dir string) error {
	rootCert, err := k8sConfigMap("istio-ca-root-cert", "istio-system")
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(dir+"/root-cert.pem", []byte(rootCert.Data["root-cert.pem"]), tempPerms); err != nil {
		return err
	}

	args := strings.Split("run istio.io/istio/security/tools/generate_cert -client -host spiffee://cluster.local/vm/vmname --out-priv key.pem --out-cert cert-chain.pem -mode citadel", " ")
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	if err = cmd.Run(); err != nil {
		return err
	}
	return nil
}

func createMeshConfig(wg *clientv1alpha3.WorkloadGroup, cluster *containerpb.Cluster, dir string) error {
	istio, err := k8sConfigMap("istio", "istio-system")
	if err != nil {
		return err
	}

	// TODO: get unmarshal fully working w/o error using mesh
	var mesh meshconfig.MeshConfig
	meshJSON, err := yaml.YAMLToJSON([]byte(istio.Data["mesh"]))
	if err != nil {
		return err
	}
	if err = jsonpb.Unmarshal(bytes.NewReader(meshJSON), &mesh); err != nil {
		return err
	}

	// TODO: check that these are all the correct vals
	md := mesh.DefaultConfig.ProxyMetadata
	md["CANONICAL_SERVICE"] = "mock service"
	md["CANONICAL_REVISION"] = "mock version"
	md["DNS_AGENT"] = ""
	md["POD_NAMESPACE"] = wg.Namespace
	md["SERVICE_ACCOUNT"] = wg.Spec.ServiceAccount
	md["TRUST_DOMAIN"] = mesh.TrustDomain

	md["ISTIO_META_CLUSTER_ID"] = "mock id"
	md["ISTIO_META_MESH_ID"] = string(mesh.DefaultConfig.MeshId)
	md["ISTIO_META_NETWORK"] = wg.Spec.Network
	if ports, err := json.Marshal(wg.Spec.Ports); err == nil {
		md["ISTIO_META_POD_PORTS"] = string(ports)
	}
	md["ISTIO_META_WORKLOAD_NAME"] = wg.Name
	wg.Spec.Labels["service.istio.io/canonical-name"] = md["CANONICAL_SERVICE"]
	wg.Spec.Labels["service.istio.io/canonical-version"] = md["CANONICAL_REVISION"]
	if labels, err := json.Marshal(wg.Spec.Labels); err == nil {
		md["ISTIO_META_JSON_LABELS"] = string(labels)
	}

	meshYAML, err := yaml.Marshal(mesh)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dir+"/mesh", meshYAML, tempPerms)
}

// Packs files inside source into target.tar
func Tar(source, target string) error {
	target = fmt.Sprintf("%s.tar", filepath.Base(target))
	tarfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer tarfile.Close()
	tw := tar.NewWriter(tarfile)
	defer tw.Close()

	info, err := os.Stat(source)
	if err != nil {
		return nil
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	return filepath.Walk(source,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			if baseDir != "" {
				header.Name = strings.TrimPrefix(path, source)
			}

			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tw, file)
			return err
		})
}

func mapToString(m map[string]string) string {
	var b strings.Builder
	for k, v := range m {
		fmt.Fprintf(&b, "%s=%s\n", k, v)
	}
	return b.String()
}
