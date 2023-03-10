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

package processlog

import (
	"path/filepath"
	"testing"
	"time"

	"istio.io/istio/pilot/test/util"
	"istio.io/istio/pkg/test/env"
	"istio.io/istio/tools/bug-report/pkg/config"
)

func TestTimeRangeFilter(t *testing.T) {
	testDataDir := filepath.Join(env.IstioSrc, "tools/bug-report/pkg/testdata/")
	b := util.ReadFile(t, filepath.Join(testDataDir, "input/ingress.log"))
	inLog := string(b)
	tests := []struct {
		name      string
		start     string
		end       string
		wantEmpty bool
	}{
		{
			name:      "wantEmpty",
			start:     "2020-05-29T23:37:27.285018Z",
			end:       "2020-06-10T23:37:27.285018Z",
			wantEmpty: true,
		},
		{
			name:  "range_equals",
			start: "2020-06-29T23:37:27.285053Z",
			end:   "2020-06-29T23:37:27.285885Z",
		},
		{
			name:  "range_not_equals",
			start: "2020-06-29T23:37:27.285052Z",
			end:   "2020-06-29T23:37:27.285886Z",
		},
		{
			name:  "multi_line_entries",
			start: "2020-06-29T23:37:27.287895Z",
			end:   "2020-06-29T23:37:27.287996Z",
		},
		{
			name:      "reverse",
			start:     "2020-06-29T23:37:27.287996Z",
			end:       "2020-06-29T23:37:27.287895Z",
			wantEmpty: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b []byte
			if !tt.wantEmpty {
				b = util.ReadFile(t, filepath.Join(testDataDir, "output", tt.name+".log"))
			}
			want := string(b)
			start, err := time.Parse(time.RFC3339Nano, tt.start)
			if err != nil {
				t.Fatal(err)
			}
			end, err := time.Parse(time.RFC3339Nano, tt.end)
			if err != nil {
				t.Fatal(err)
			}
			got := getTimeRange(inLog, start, end)
			if got != want {
				t.Errorf("%s: got:\n%s\n\nwant:\n%s\n", tt.name, got, want)
			}
		})
	}
}

func TestProcessZtunnel(t *testing.T) {
	testDataDir := filepath.Join(env.IstioSrc, "tools/bug-report/pkg/testdata/")
	b := util.ReadFile(t, filepath.Join(testDataDir, "input/ztunnel.log"))
	inLog := string(b)
	tests := []struct {
		name  string
		start string
		end   string
	}{
		{
			name:  "only_config_ztunnel",
			start: "2020-05-29T23:37:27.285018Z",
			end:   "2020-06-10T23:37:27.285018Z",
		},
		{
			name:  "range_equals_ztunnel",
			start: "2023-03-08T06:40:11.080935Z",
			end:   "2023-03-08T06:40:11.080935Z",
		},
		{
			name:  "range_not_equals_ztunnel",
			start: "2023-03-08T06:40:05.959283Z",
			end:   "2023-03-08T06:40:26.471154Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var b []byte
			b = util.ReadFile(t, filepath.Join(testDataDir, "output", tt.name+".log"))
			want := string(b)
			start, err := time.Parse(time.RFC3339Nano, tt.start)
			if err != nil {
				t.Fatal(err)
			}
			end, err := time.Parse(time.RFC3339Nano, tt.end)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.BugReportConfig{
				StartTime: start,
				EndTime:   end,
			}
			got, _ := ProcessZtunnel(cfg, inLog)
			if got != want {
				t.Errorf("%s: got:\n%s\n\nwant:\n%s\n", tt.name, got, want)
			}
		})
	}
}
