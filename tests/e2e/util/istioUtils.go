package util

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/golang/glog"
)

const (
	istioctl_url = "ISTIOCTL_URL"
)

var (
	remotePath = flag.String("istioctl_url", os.Getenv(istioctl_url), "URL to download istioctl")
)

// Istioctl gathers istioctl information
type Istioctl struct {
	remotePath string
	binaryPath string
	namespace  string
}

// NewIstioctl create a new istioctl by given temp dir
func NewIstioctl(tmpDir, namespace string) *Istioctl {
	return &Istioctl{
		remotePath: *remotePath,
		binaryPath: filepath.Join(tmpDir, "/istioctl"),
		namespace:  namespace,
	}
}

// DownloadIstioctl download Istioctl binary
func (i *Istioctl) DownloadIstioctl() error {
	var usr, err = user.Current()
	if err != nil {
		return err
	}
	homeDir := usr.HomeDir

	if err = HTTPDownload(i.binaryPath, i.remotePath+"/istioctl-linux"); err != nil {
		return err
	}
	if err = os.Chmod(i.binaryPath, 0755); err != nil {
		return err
	}
	i.binaryPath = fmt.Sprintf("%s -c %s/.kube/config", i.binaryPath, homeDir)
	return nil
}

// KubeInject use istio kube-inject to create new yaml with a proxy as sidecar
func (i *Istioctl) KubeInject(yamlFile, svcName, yamlDir, proxyHub, proxyTag string) (string, error) {
	injectedYamlFile := filepath.Join(yamlDir, "injected-"+svcName+"-app.yaml")
	if _, err := Shell(fmt.Sprintf("%s kube-inject -f %s -o %s --hub %s --tag %s -n %s",
		i.binaryPath, yamlFile, injectedYamlFile, proxyHub, proxyTag, i.namespace)); err != nil {
		glog.Errorf("Kube-inject failed for service %s", svcName)
		return "", err
	}
	return injectedYamlFile, nil
}

// CreateRule create new rule(s)
func (i *Istioctl) CreateRule(rule string) error {
	_, err := Shell(fmt.Sprintf("%s -n %s create -f %s", i.binaryPath, i.namespace, rule))
	return err
}

// ReplaceRule replace rule(s)
func (i *Istioctl) ReplaceRule(rule string) error {
	_, err := Shell(fmt.Sprintf("%s -n %s replace -f %s", i.binaryPath, i.namespace, GetTestRuntimePath(rule)))
	return err
}
