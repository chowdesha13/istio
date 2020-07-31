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
	"fmt"
	"strings"
	"testing"
)

var (
	defaultYAML = `apiVersion: networking.istio.io/v1alpha3
kind: WorkloadGroup
metadata:
  name: foo
  namespace: bar
spec:
  template:
    metadata:
      labels: {}
    spec:
      ports: {}
      serviceAccount: default
`

	customYAML = `apiVersion: networking.istio.io/v1alpha3
kind: WorkloadGroup
metadata:
  name: foo
  namespace: bar
spec:
  template:
    metadata:
      labels:
        app: foo
        bar: baz
    spec:
      ports:
        grpc: 3550
        http: 8080
      serviceAccount: test
`
)

func TestCreateGroup(t *testing.T) {
	cases := []testcase{
		{
			description:       "Invalid command args - missing service name and namespace",
			args:              strings.Split("experimental workload group create", " "),
			expectedException: true,
			expectedOutput:    "Error: expecting a service name\n",
		},
		{
			description:       "Invalid command args - missing service name",
			args:              strings.Split("experimental workload group create --namespace bar", " "),
			expectedException: true,
			expectedOutput:    "Error: expecting a service name\n",
		},
		{
			description:       "Invalid command args - missing service namespace",
			args:              strings.Split("experimental workload group create --name foo", " "),
			expectedException: true,
			expectedOutput:    "Error: expecting a service namespace\n",
		},
		{
			description:       "valid case - minimal flags, infer defaults",
			args:              strings.Split("experimental workload group create --name foo --namespace bar", " "),
			expectedException: false,
			expectedOutput:    defaultYAML,
		},
		{
			description: "valid case - create full workload group",
			args: strings.Split("experimental workload group create --name foo --namespace bar --labels app=foo,bar=baz "+
				" --ports grpc=3550,http=8080 --serviceAccount test", " "),
			expectedException: false,
			expectedOutput:    customYAML,
		},
		{
			description: "valid case - create full workload group with shortnames",
			args: strings.Split("experimental workload group create --name foo -n bar -l app=foo,bar=baz -p grpc=3550,http=8080"+
				" --serviceAccount test", " "),
			expectedException: false,
			expectedOutput:    customYAML,
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d %s", i, c.description), func(t *testing.T) {
			verifyAddToMeshOutput(t, c)
		})
	}
}

func TestGenerateConfig(t *testing.T) {
	cases := []testcase{
		{
			description:       "Invalid command args - missing valid input spec",
			args:              strings.Split("experimental workload entry configure -o temp --clusterID cid", " "),
			expectedException: true,
			expectedOutput:    "Error: expecting a WorkloadGroup artifact file or both the workload name and namespace\n",
		},
		{
			description:       "Invalid command args - valid filename input but missing output filename",
			args:              strings.Split("experimental workload entry configure -f file --clusterID cid", " "),
			expectedException: true,
			expectedOutput:    "Error: expecting an output filename\n",
		},
		{
			description:       "Invalid command args - valid kubectl input but missing output filename",
			args:              strings.Split("experimental workload entry configure --name foo -n bar --clusterID cid", " "),
			expectedException: true,
			expectedOutput:    "Error: expecting an output filename\n",
		},
		{
			description:       "Invalid command args - missing cluster id",
			args:              strings.Split("experimental workload entry configure --file fname --output ./config -", " "),
			expectedException: true,
			expectedOutput:    "Error: expecting a cluster id\n",
		},
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("case %d %s", i, c.description), func(t *testing.T) {
			verifyAddToMeshOutput(t, c)
		})
	}
}
