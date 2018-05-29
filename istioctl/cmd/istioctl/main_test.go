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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildClientConfig(t *testing.T) {
	config1, err := generateKubeConfig("1.1.1.1")
	if err != nil {
		t.Errorf("Failed to create a sample kubernetes config file. Err: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(config1))
	config2, err := generateKubeConfig("2.2.2.2")
	if err != nil {
		t.Errorf("Failed to create a sample kubernetes config file. Err: %v", err)
	}
	defer os.RemoveAll(filepath.Dir(config2))

	type args struct {
		masterURL      string
		kubeconfigPath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		host    string
	}{
		{
			name:    "EmptyStringsArgs",
			args:    args{masterURL: "", kubeconfigPath: ""},
			wantErr: true,
			host:    "",
		},
		{
			name:    "MalformedKubeconfigPath",
			args:    args{masterURL: "", kubeconfigPath: "missing"},
			wantErr: true,
			host:    "",
		},
		{
			name:    "SinglePath",
			args:    args{masterURL: "", kubeconfigPath: config1},
			wantErr: false,
			host:    "https://1.1.1.1:8001",
		},
		{
			name:    "MultiplePathsFirst",
			args:    args{masterURL: "", kubeconfigPath: fmt.Sprintf("%s:%s", config1, config2)},
			wantErr: false,
			host:    "https://1.1.1.1:8001",
		},
		{
			name:    "MultiplePathsSecond",
			args:    args{masterURL: "", kubeconfigPath: fmt.Sprintf("missing:%s", config2)},
			wantErr: false,
			host:    "https://2.2.2.2:8001",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := BuildClientConfig(tt.args.masterURL, tt.args.kubeconfigPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildClientConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if resp != nil && resp.Host != tt.host {
				t.Errorf("Incorrect host. Got: %s, Want: %s", resp.Host, tt.host)
			}
		})
	}
}

func generateKubeConfig(host string) (string, error) {
	tempDir, err := ioutil.TempDir("/tmp/", ".kube")
	if err != nil {
		return "", err
	}
	filePath := filepath.Join(tempDir, "config")

	template := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    insecure-skip-tls-verify: true
    server: https://%s:8001
  name: cluster.local
contexts:
- context:
    cluster: cluster.local
    namespace: default
    user: admin
  name: cluster.local-context
current-context: cluster.local-context
preferences: {}
users:
- name: admin
  user:
    token: sdsddsd`

	sampleConfig := fmt.Sprintf(template, host)
	err = ioutil.WriteFile(filePath, []byte(sampleConfig), 0644)
	if err != nil {
		return "", err
	}
	return filePath, nil
}
