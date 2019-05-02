// +build cgo,linux

/*
Copyright 2015 The Kubernetes Authors.

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

package cadvisor

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/google/cadvisor/cache/memory"
	cadvisormetrics "github.com/google/cadvisor/container"
	"github.com/google/cadvisor/events"
	cadvisorapi "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	"github.com/google/cadvisor/manager"
	"github.com/google/cadvisor/metrics"
	"github.com/google/cadvisor/utils/sysfs"
	"k8s.io/klog"
	"k8s.io/kubernetes/pkg/kubelet/types"
)

type cadvisorClient struct {
	imageFsInfoProvider ImageFsInfoProvider
	rootPath            string
	manager.Manager
}

var _ Interface = new(cadvisorClient)

// TODO(vmarmol): Make configurable.
// The amount of time for which to keep stats in memory.
const statsCacheDuration = 2 * time.Minute
const maxHousekeepingInterval = 15 * time.Second
const defaultHousekeepingInterval = 10 * time.Second
const allowDynamicHousekeeping = true

func init() {
	// Override cAdvisor flag defaults.
	flagOverrides := map[string]string{
		// Override the default cAdvisor housekeeping interval.
		"housekeeping_interval": defaultHousekeepingInterval.String(),
		// Disable event storage by default.
		"event_storage_event_limit": "default=0",
		"event_storage_age_limit":   "default=0",
	}
	for name, defaultValue := range flagOverrides {
		if f := flag.Lookup(name); f != nil {
			f.DefValue = defaultValue
			f.Value.Set(defaultValue)
		} else {
			klog.Errorf("Expected cAdvisor flag %q not found", name)
		}
	}
}

func containerLabels(c *cadvisorapi.ContainerInfo) map[string]string {
	// Prometheus requires that all metrics in the same family have the same labels,
	// so we arrange to supply blank strings for missing labels
	var name, image, podName, namespace, containerName string
	if len(c.Aliases) > 0 {
		name = c.Aliases[0]
	}
	image = c.Spec.Image
	if v, ok := c.Spec.Labels[types.KubernetesPodNameLabel]; ok {
		podName = v
	}
	if v, ok := c.Spec.Labels[types.KubernetesPodNamespaceLabel]; ok {
		namespace = v
	}
	if v, ok := c.Spec.Labels[types.KubernetesContainerNameLabel]; ok {
		containerName = v
	}
	set := map[string]string{
		metrics.LabelID:    c.Name,
		metrics.LabelName:  name,
		metrics.LabelImage: image,
		"pod_name":         podName,
		"namespace":        namespace,
		"container_name":   containerName,
	}
	return set
}

// New creates a cAdvisor and exports its API on the specified port if port > 0.
func New(imageFsInfoProvider ImageFsInfoProvider, rootPath string, usingLegacyStats bool) (Interface, error) {
	sysFs := sysfs.NewRealSysFs()

	includedMetrics := cadvisormetrics.MetricSet{
		cadvisormetrics.CpuUsageMetrics:         struct{}{},
		cadvisormetrics.MemoryUsageMetrics:      struct{}{},
		cadvisormetrics.CpuLoadMetrics:          struct{}{},
		cadvisormetrics.DiskIOMetrics:           struct{}{},
		cadvisormetrics.NetworkUsageMetrics:     struct{}{},
		cadvisormetrics.AcceleratorUsageMetrics: struct{}{},
		cadvisormetrics.AppMetrics:              struct{}{},
	}
	if usingLegacyStats {
		includedMetrics[cadvisormetrics.DiskUsageMetrics] = struct{}{}
	}

	// collect metrics for all cgroups
	rawContainerCgroupPathPrefixWhiteList := []string{"/"}
	// Create and start the cAdvisor container manager.
	m, err := manager.New(memory.New(statsCacheDuration, nil), sysFs, maxHousekeepingInterval, allowDynamicHousekeeping, includedMetrics, http.DefaultClient, rawContainerCgroupPathPrefixWhiteList)
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(rootPath); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(path.Clean(rootPath), 0750); err != nil {
				return nil, fmt.Errorf("error creating root directory %q: %v", rootPath, err)
			}
		} else {
			return nil, fmt.Errorf("failed to Stat %q: %v", rootPath, err)
		}
	}

	cadvisorClient := &cadvisorClient{
		imageFsInfoProvider: imageFsInfoProvider,
		rootPath:            rootPath,
		Manager:             m,
	}

	return cadvisorClient, nil
}

func (cc *cadvisorClient) Start() error {
	return cc.Manager.Start()
}

func (cc *cadvisorClient) ContainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (*cadvisorapi.ContainerInfo, error) {
	return cc.GetContainerInfo(name, req)
}

func (cc *cadvisorClient) ContainerInfoV2(name string, options cadvisorapiv2.RequestOptions) (map[string]cadvisorapiv2.ContainerInfo, error) {
	return cc.GetContainerInfoV2(name, options)
}

func (cc *cadvisorClient) VersionInfo() (*cadvisorapi.VersionInfo, error) {
	return cc.GetVersionInfo()
}

func (cc *cadvisorClient) SubcontainerInfo(name string, req *cadvisorapi.ContainerInfoRequest) (map[string]*cadvisorapi.ContainerInfo, error) {
	infos, err := cc.SubcontainersInfo(name, req)
	if err != nil && len(infos) == 0 {
		return nil, err
	}

	result := make(map[string]*cadvisorapi.ContainerInfo, len(infos))
	for _, info := range infos {
		result[info.Name] = info
	}
	return result, err
}

func (cc *cadvisorClient) MachineInfo() (*cadvisorapi.MachineInfo, error) {
	return cc.GetMachineInfo()
}

func (cc *cadvisorClient) ImagesFsInfo() (cadvisorapiv2.FsInfo, error) {
	label, err := cc.imageFsInfoProvider.ImageFsInfoLabel()
	if err != nil {
		return cadvisorapiv2.FsInfo{}, err
	}
	return cc.getFsInfo(label)
}

func (cc *cadvisorClient) RootFsInfo() (cadvisorapiv2.FsInfo, error) {
	return cc.GetDirFsInfo(cc.rootPath)
}

func (cc *cadvisorClient) getFsInfo(label string) (cadvisorapiv2.FsInfo, error) {
	res, err := cc.GetFsInfo(label)
	if err != nil {
		return cadvisorapiv2.FsInfo{}, err
	}
	if len(res) == 0 {
		return cadvisorapiv2.FsInfo{}, fmt.Errorf("failed to find information for the filesystem labeled %q", label)
	}
	// TODO(vmarmol): Handle this better when a label has more than one image filesystem.
	if len(res) > 1 {
		klog.Warningf("More than one filesystem labeled %q: %#v. Only using the first one", label, res)
	}

	return res[0], nil
}

func (cc *cadvisorClient) WatchEvents(request *events.Request) (*events.EventChannel, error) {
	return cc.WatchForEvents(request)
}
