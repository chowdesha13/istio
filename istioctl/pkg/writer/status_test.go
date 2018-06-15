package writer

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"

	"istio.io/istio/tests/util"
)

func TestStatusWriter_PrintAll(t *testing.T) {
	tests := []struct {
		name    string
		input   [][]byte
		want    string
		wantErr bool
	}{
		{
			name: "prints multiple pilot inputs to buffer in alphabetical order by pod name",
			input: [][]byte{
				[]byte(`[{"proxy":"proxy2","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001"}]`),
				[]byte(`[{"proxy":"proxy1","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 22:00:00 +0000 UTC m=+0.000000001"}]`),
			},
			want: "testdata/multiplestatus.txt",
		},
		{
			name: "prints single pilot input to buffer in alphabetical order by pod name",
			input: [][]byte{
				[]byte(`[{"proxy":"proxy2","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001"},
						{"proxy":"proxy1","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 22:00:00 +0000 UTC m=+0.000000001"}]`),
			},
			want: "testdata/multiplestatus.txt",
		},
		{
			name: "error if given non-syncstatus info",
			input: [][]byte{
				[]byte(`gobbledygook`),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &bytes.Buffer{}
			sw := StatusWriter{Writer: got}
			err := sw.PrintAll(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			want, _ := ioutil.ReadFile(tt.want)
			if err := util.Compare(got.Bytes(), want); err != nil {
				t.Errorf(err.Error())
			}
		})
	}
}

func TestStatusWriter_PrintSingle(t *testing.T) {
	tests := []struct {
		name      string
		input     [][]byte
		filterPod string
		want      string
		wantErr   bool
	}{
		{
			name: "prints multiple pilot inputs to buffer filtering for pod",
			input: [][]byte{
				[]byte(`[{"proxy":"proxy2","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001"}]`),
				[]byte(`[{"proxy":"proxy1","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 22:00:00 +0000 UTC m=+0.000000001"}]`),
			},
			filterPod: "proxy2",
			want:      "testdata/singlestatus.txt",
		},
		{
			name: "single pilot input to buffer filtering for pod",
			input: [][]byte{
				[]byte(`[{"proxy":"proxy2","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001"},
						{"proxy":"proxy1","sent":"2009-11-10 23:00:00 +0000 UTC m=+0.000000001","acked":"2009-11-10 22:00:00 +0000 UTC m=+0.000000001"}]`),
			},
			filterPod: "proxy2",
			want:      "testdata/singlestatus.txt",
		},
		{
			name: "error if given non-syncstatus info",
			input: [][]byte{
				[]byte(`gobbledygook`),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &bytes.Buffer{}
			sw := StatusWriter{Writer: got}
			err := sw.PrintSingle(tt.input, tt.filterPod)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			want, _ := ioutil.ReadFile(tt.want)
			if err := util.Compare(got.Bytes(), want); err != nil {
				t.Errorf(err.Error())
			}

		})
	}
}
