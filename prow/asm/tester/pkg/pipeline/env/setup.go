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

package env

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"istio.io/istio/prow/asm/tester/pkg/exec"
	"istio.io/istio/prow/asm/tester/pkg/kube"
	"istio.io/istio/prow/asm/tester/pkg/resource"
)

const (
	sharedGCPProject = "istio-prow-build"
)

func Setup(settings *resource.Settings) error {
	log.Println("🎬 start setting up the environment...")

	// Validate the settings before proceeding.
	if err := resource.ValidateSettings(settings); err != nil {
		return err
	}

	// Populate the settings that will be used in runtime.
	if err := populateRuntimeSettings(settings); err != nil {
		return err
	}

	// Fix the cluster configs before proceeding.
	if err := fixClusterConfigs(settings); err != nil {
		return err
	}

	// Inject system env vars that are required for the test flow.
	if err := injectEnvVars(settings); err != nil {
		return err
	}

	// Run the setup-env.sh
	// TODO: convert the script into Go
	setupEnvScript := filepath.Join(settings.RepoRootDir, "prow/asm/tester/scripts/setup-env.sh")
	if err := exec.Run(setupEnvScript); err != nil {
		return fmt.Errorf("error setting up the environment: %w", err)
	}

	log.Printf("Running with %q CA, %q Workload Identity Pool, %q and --vm=%t control plane.", settings.CA, settings.WIP, settings.ControlPlane, settings.UseVMs)

	return nil
}

// populate extra settings that will be used during the runtime
func populateRuntimeSettings(settings *resource.Settings) error {
	var kubectlContexts string
	var err error
	kubectlContexts, err = kube.ContextStr()
	if err != nil {
		return err
	}
	settings.KubectlContexts = kubectlContexts

	var gcrProjectID string
	if settings.ClusterType == string(resource.GKEOnGCP) {
		settings.GCPProjects = kube.ParseGCPProjectIDsFromContexts(kubectlContexts)
		// If it's using the gke clusters, use the first available project to hold the images.
		gcrProjectID = settings.GCPProjects[0]
	} else {
		// Otherwise use the shared GCP project to hold these images.
		gcrProjectID = sharedGCPProject
	}
	settings.GCRProject = gcrProjectID

	if settings.ClusterTopology == string(resource.MultiProject) {
		settings.HostGCPProject = os.Getenv("HOST_PROJECT")
	}

	return nil
}

func injectEnvVars(settings *resource.Settings) error {
	var hub, tag string
	tag = "BUILD_ID_" + os.Getenv("BUILD_ID")
	if settings.ControlPlane == string(resource.Unmanaged) {
		hub = fmt.Sprintf("gcr.io/%s/asm", settings.GCRProject)
	} else {
		hub = "gcr.io/asm-staging-images/asm-mcp-e2e-test"
	}

	var meshID string
	if settings.ClusterType == string(resource.GKEOnGCP) {
		projectNum, err := exec.RunWithOutput(
			fmt.Sprintf("gcloud projects describe %s --format=value(projectNumber)", settings.GCPProjects[0]))
		if err != nil {
			return fmt.Errorf("error getting the project number for %q: %w", settings.GCPProjects[0], err)
		}
		meshID = "proj-" + strings.TrimSpace(projectNum)
	}

	// TODO(chizhg): delete most, if not all, the env var injections after we convert all the
	// bash to Go and remove the env var dependencies.
	envVars := map[string]string{
		// Run the Go tests with verbose logging.
		"T": "-v",
		// Do not start a container to run the build.
		"BUILD_WITH_CONTAINER": "0",
		// The GCP project we use when testing with multicloud clusters, or when we need to
		// hold some GCP resources that are shared across multiple jobs that are run in parallel.
		"SHARED_GCP_PROJECT": sharedGCPProject,

		"GCR_PROJECT_ID":   settings.GCRProject,
		"CONTEXT_STR":      settings.KubectlContexts,
		"CONFIG_DIR":       filepath.Join(settings.RepoRootDir, "prow/asm/tester/configs"),
		"CLUSTER_TYPE":     settings.ClusterType,
		"CLUSTER_TOPOLOGY": settings.ClusterTopology,
		"FEATURE_TO_TEST":  settings.FeatureToTest,

		// exported TAG and HUB are used for ASM installation, and as the --istio.test.tag and
		// --istio-test.hub flags of the testing framework
		"TAG": tag,
		"HUB": hub,

		"MESH_ID": meshID,

		"CONTROL_PLANE":        settings.ControlPlane,
		"CA":                   settings.CA,
		"WIP":                  settings.WIP,
		"REVISION_CONFIG_FILE": settings.RevisionConfig,
		"TEST_TARGET":          settings.TestTarget,
		"DISABLED_TESTS":       settings.DisabledTests,

		"USE_VM":        strconv.FormatBool(settings.UseVMs),
		"STATIC_VMS":    settings.VMStaticConfigDir,
		"VM_DISTRO":     settings.VMImageFamily,
		"IMAGE_PROJECT": settings.VMImageProject,
	}

	for name, val := range envVars {
		log.Printf("Set env var: %s=%s", name, val)
		if err := os.Setenv(name, val); err != nil {
			return fmt.Errorf("error setting env var %q to %q", name, val)
		}
	}

	return nil
}

// Fix the cluster configs to meet the test requirements for ASM.
// These fixes are considered as hacky and temporary, ideally in the future they
// should all be handled by the corresponding deployer.
func fixClusterConfigs(settings *resource.Settings) error {
	switch settings.ClusterType {
	case string(resource.GKEOnGCP):
		return fixGKE(settings)
	case string(resource.OnPrem):
		return fixOnPrem(settings)
	case string(resource.BareMetal):
		return fixBareMetal(settings)
	case string(resource.GKEOnAWS):
		return fixAWS(settings)
	}

	return nil
}

func fixGKE(settings *resource.Settings) error {
	if settings.ClusterTopology == string(resource.MultiProject) {
		// For MULTIPROJECT_MULTICLUSTER topology, firewall rules need to be added to
		// allow the clusters talking with each other for security tests.
		// See the details in b/175599359 and b/177919868
		createFirewallCmd := fmt.Sprintf("gcloud compute --project=%q firewall-rules create extended-firewall-rule --network=test-network --allow=tcp,udp,icmp --direction=INGRESS", os.Getenv("HOST_PROJECT"))
		if err := exec.Run(createFirewallCmd); err != nil {
			return fmt.Errorf("error creating the firewall rules for GKE multiproject tests: %w", err)
		}
	}

	if settings.FeatureToTest == "VPC_SC" {
		networkName := "default"
		if settings.ClusterTopology == string(resource.MultiProject) {
			networkName = "test-network"
		}
		// Create the route as per the user guide in https://docs.google.com/document/d/11yYDxxI-fbbqlpvUYRtJiBmGdY_nIKPJLbssM3YQtKI/edit#heading=h.e2laig460f1d.
		createRouteCmd := fmt.Sprintf(`gcloud compute routes create restricted-vip --network=%s --destination-range=199.36.153.4/30 \
			--next-hop-gateway=default-internet-gateway`, networkName)
		if err := exec.Run(createRouteCmd); err != nil {
			return fmt.Errorf("error creating the restricted-vip route for VPC-SC testing: %w", err)
		}

		if settings.ClusterTopology == string(resource.MultiProject) {
			for _, project := range settings.GCPProjects {
				updateSubnetCmd := fmt.Sprintf(`gcloud compute networks subnets update "test-network-%s" \
				 	--project=%s \
					--region=us-central1 \
					--enable-private-ip-google-access`, project, settings.HostGCPProject)
				if err := exec.Run(updateSubnetCmd); err != nil {
					return fmt.Errorf("error updating the subnet for VPC-SC testing: %w", err)
				}
			}
		}
	}

	return nil
}

// Keeps only the user-kubeconfig.yaml entries in the KUBECONFIG for onprem
// by removing others including the admin-kubeconfig.yaml entries.
// This function will modify the KUBECONFIG env variable.
func fixOnPrem(settings *resource.Settings) error {
	return filterKubeconfigFiles(func(name string) bool {
		return strings.HasSuffix(name, "user-kubeconfig.yaml")
	})
}

// Keeps only the artifacts/kubeconfig entries in the KUBECONFIG for baremetal
// by removing any others entries.
// This function will modify the KUBECONFIG env variable
func fixBareMetal(settings *resource.Settings) error {
	err := filterKubeconfigFiles(func(name string) bool {
		return strings.Contains(name, ".artifacts/kubeconfig")
	})
	if err != nil {
		return err
	}

	// TODO: init_baremetal_http_proxy
	return nil
}

// Removes gke_aws_management.conf entry from the KUBECONFIG for aws
// This function will modify the KUBECONFIG env variable
func fixAWS(settings *resource.Settings) error {
	err := filterKubeconfigFiles(func(name string) bool {
		return !strings.HasSuffix(name, "gke_aws_management.conf")
	})
	if err != nil {
		return err
	}

	// TODO: aws::init
	return nil
}

func filterKubeconfigFiles(shouldKeep func(string) bool) error {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		return errors.New("KUBECONFIG env var cannot be empty")
	}

	files := strings.Split(kubeconfig, string(os.PathListSeparator))
	filteredFiles := make([]string, 0)
	for _, f := range files {
		if shouldKeep(f) {
			filteredFiles = append(filteredFiles, f)
		}
	}
	os.Setenv("KUBECONFIG", strings.Join(filteredFiles, string(os.PathListSeparator)))

	return nil
}
