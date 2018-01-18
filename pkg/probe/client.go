// Copyright 2018 Istio Authors
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

package probe

import (
	"fmt"
	"os"
	"time"
)

// PathExists checks if the specified path exists or not. This will be used
// by the k8s probe client commandline tool.
func PathExists(path string) error {
	_, err := os.Stat(path)
	return err
}

// Client is the interface to check the status of a probe controller.
type Client interface {
	GetStatus() error
}

type fileClient struct {
	opt *Options
}

// NewFileClient creates an instance of Client based on the file status specified
// in the path. The specified period is the interval of the probe, so if this
func NewFileClient(opt *Options) Client {
	return &fileClient{opt}
}

func (fc *fileClient) GetStatus() error {
	stat, err := os.Stat(fc.opt.Path)
	if err != nil {
		return err
	}
	now := time.Now()
	// Sometimes filesystem / goroutine scheduling takes time, some buffer should be
	// allowed for the validity of a file.
	const jitter = 10 * time.Millisecond
	if mtime := stat.ModTime(); now.Sub(mtime) > fc.opt.ProbeInterval+jitter {
		return fmt.Errorf("file %s is too old (last modified time %v, should be within %v)", fc.opt.Path, mtime, fc.opt.ProbeInterval+jitter)
	}
	return nil
}
