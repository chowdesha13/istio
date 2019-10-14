package multicluster

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
)

type MeshDescConfigHints struct {
	// hints for generating config
	SelfSigned bool `json:selfSigned,omitempty`
}

// MeshDesc describes the topology of a multi-cluster mesh. The clusters in the mesh reference the active
// Kubeconfig file as described by https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig.
type MeshDesc struct {
	// Mesh Identifier.
	MeshID string `json:"mesh_id,omitempty"`

	// Collection of clusters in the multi-cluster mesh. Clusters are indexed by Context name and
	// reference clusters defined in the Kubeconfig following kubectl precedence rules.
	Clusters map[string]*ClusterDesc `json:"clusters,omitempty"`

	// Hints for how multi-cluster configuration should be generated.
	ConfigHints *MeshDescConfigHints `json:configHints,omitempty`
}

// ClusterDesc describes attributes of a cluster and the desired state of joining the mesh.
type ClusterDesc struct {
	// Name of the cluster's network
	Network string `json:"network,omitempty"`

	// Optional Namespace override of the Istio control plane. `istio-system` if not set.
	Namespace string `json:"Namespace,omitempty"`

	// Optional service account to use for cross-cluster authentication. `istio-multi` if not set.
	ServiceAccountReader string `json:"serviceAccountReader"`

	// When true, disables enforcement of common trust with this cluster and the rest of the mesh.
	DisableTrust bool `json:"joinTrust,omitempty"`

	// When true, disables linking the service registry of this cluster with other clusters in the mesh.
	DisableServiceDiscovery bool `json:"joinServiceDiscovery,omitempty"`
}

type Mesh struct {
	meshID   string
	clusters map[string]*KubeCluster // by context
	sorted   []*KubeCluster
	hints    *MeshDescConfigHints
}

func (m *Mesh) forEachCluster(env Environment, fn func(c *KubeCluster) (cont bool, err error)) error {
	for _, c := range m.sorted {
		if cont, err := fn(c); err != nil {
			fmt.Fprintf(env.Stdout(), "error: cluster %v: %v\n", c.context, err)
			if !cont {
				return err
			}
		}
	}
	return nil
}

func LoadMeshDesc(filename string, env Environment) (*MeshDesc, error) {
	out, err := env.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read %v: %v", filename, err)
	}
	md := &MeshDesc{}
	if err := yaml.Unmarshal(out, md); err != nil {
		return nil, err
	}
	return md, nil
}

func NewMesh(kubeconfig string, md *MeshDesc, env Environment) (*Mesh, error) {

	clusters := make(map[string]*KubeCluster)
	for context, clusterDesc := range md.Clusters {
		cluster, err := NewCluster(kubeconfig, context, *clusterDesc, env)
		if err != nil {
			return nil, fmt.Errorf("error discovering %v: %v", context, err)
		}
		clusters[context] = cluster
	}

	sortedClusters := make([]*KubeCluster, 0, len(clusters))
	for _, other := range clusters {
		sortedClusters = append(sortedClusters, other)
	}
	sort.Slice(sortedClusters, func(i, j int) bool {
		return strings.Compare(sortedClusters[i].uid, sortedClusters[j].uid) < 0
	})

	return &Mesh{
		meshID:   md.MeshID,
		clusters: make(map[string]*KubeCluster),
		sorted:   sortedClusters,
		hints:    md.ConfigHints,
	}, nil
}

func meshFromFileDesc(filename, kubeconfig string, env Environment) (*Mesh, error) {
	md, err := LoadMeshDesc(filename, env)
	if err != nil {
		return nil, err
	}
	mesh, err := NewMesh(kubeconfig, md, env)
	if err != nil {
		return nil, err
	}
	return mesh, err
}

func NewMulticlusterCommand() *cobra.Command {
	c := &cobra.Command{
		Use:     "multicluster",
		Short:   `Commands to assist in managing a multi-cluster mesh`,
		Aliases: []string{"mc"},
	}

	c.AddCommand(
		NewGenerateCommand(),
		NewJoinCommand(),
		NewCheckCommand(),
	)

	return c
}
