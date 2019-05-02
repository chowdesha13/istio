/*
Copyright 2014 The Kubernetes Authors.

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

package cloudprovider

import (
	"fmt"
	"io"
	"os"
	"sync"

	"k8s.io/klog"
)

// Factory is a function that returns a cloudprovider.Interface.
// The config parameter provides an io.Reader handler to the factory in
// order to load specific configurations. If no configuration is provided
// the parameter is nil.
type Factory func(config io.Reader) (Interface, error)

// All registered cloud providers.
var (
	providersMutex           sync.Mutex
	providers                = make(map[string]Factory)
	deprecatedCloudProviders = []struct {
		name     string
		external bool
		detail   string
	}{
		{"aws", false, "The AWS provider is deprecated and will be removed in a future release"},
		{"azure", false, "The Azure provider is deprecated and will be removed in a future release"},
		{"cloudstack", false, "The CloudStack Controller project is no longer maintained."},
		{"gce", false, "The GCE provider is deprecated and will be removed in a future release"},
		{"openstack", true, "https://github.com/kubernetes/cloud-provider-openstack"},
		{"ovirt", false, "The ovirt Controller project is no longer maintained."},
		{"photon", false, "The Photon Controller project is no longer maintained."},
		{"vsphere", false, "The vSphere provider is deprecated and will be removed in a future release"},
	}
)

const externalCloudProvider = "external"

// RegisterCloudProvider registers a cloudprovider.Factory by name.  This
// is expected to happen during app startup.
func RegisterCloudProvider(name string, cloud Factory) {
	providersMutex.Lock()
	defer providersMutex.Unlock()
	if _, found := providers[name]; found {
		klog.Fatalf("Cloud provider %q was registered twice", name)
	}
	klog.V(1).Infof("Registered cloud provider %q", name)
	providers[name] = cloud
}

// IsCloudProvider returns true if name corresponds to an already registered
// cloud provider.
func IsCloudProvider(name string) bool {
	providersMutex.Lock()
	defer providersMutex.Unlock()
	_, found := providers[name]
	return found
}

// GetCloudProvider creates an instance of the named cloud provider, or nil if
// the name is unknown.  The error return is only used if the named provider
// was known but failed to initialize. The config parameter specifies the
// io.Reader handler of the configuration file for the cloud provider, or nil
// for no configuration.
func GetCloudProvider(name string, config io.Reader) (Interface, error) {
	providersMutex.Lock()
	defer providersMutex.Unlock()
	f, found := providers[name]
	if !found {
		return nil, nil
	}
	return f(config)
}

// Detects if the string is an external cloud provider
func IsExternal(name string) bool {
	return name == externalCloudProvider
}

// InitCloudProvider creates an instance of the named cloud provider.
func InitCloudProvider(name string, configFilePath string) (Interface, error) {
	var cloud Interface
	var err error

	if name == "" {
		klog.Info("No cloud provider specified.")
		return nil, nil
	}

	if IsExternal(name) {
		klog.Info("External cloud provider specified")
		return nil, nil
	}

	for _, provider := range deprecatedCloudProviders {
		if provider.name == name {
			detail := provider.detail
			if provider.external {
				detail = fmt.Sprintf("Please use 'external' cloud provider for %s: %s", name, provider.detail)
			}
			klog.Warningf("WARNING: %s built-in cloud provider is now deprecated. %s", name, detail)

			break
		}
	}

	if configFilePath != "" {
		var config *os.File
		config, err = os.Open(configFilePath)
		if err != nil {
			klog.Fatalf("Couldn't open cloud provider configuration %s: %#v",
				configFilePath, err)
		}

		defer config.Close()
		cloud, err = GetCloudProvider(name, config)
	} else {
		// Pass explicit nil so plugins can actually check for nil. See
		// "Why is my nil error value not equal to nil?" in golang.org/doc/faq.
		cloud, err = GetCloudProvider(name, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("could not init cloud provider %q: %v", name, err)
	}
	if cloud == nil {
		return nil, fmt.Errorf("unknown cloud provider %q", name)
	}

	return cloud, nil
}
