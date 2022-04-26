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

package wasm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWasmHTTPFetch(t *testing.T) {
	var ts *httptest.Server

	// Shorten the initial backoff for testing
	httpInitialBackoff = time.Microsecond

	cases := []struct {
		name           string
		handler        func(http.ResponseWriter, *http.Request, int)
		wantNumRequest int
		wantError      string
	}{
		{
			name: "download ok",
			handler: func(w http.ResponseWriter, r *http.Request, num int) {
				fmt.Fprintln(w, "wasm")
			},
			wantNumRequest: 1,
		},
		{
			name: "download retry",
			handler: func(w http.ResponseWriter, r *http.Request, num int) {
				if num <= 2 {
					w.WriteHeader(500)
				} else {
					fmt.Fprintln(w, "wasm")
				}
			},
			wantNumRequest: 4,
		},
		{
			name: "download max retry",
			handler: func(w http.ResponseWriter, r *http.Request, num int) {
				w.WriteHeader(500)
			},
			wantNumRequest: 5,
			wantError:      "wasm module download failed, last error: wasm module download request failed: status code 500",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotNumRequest := 0
			wantWasmModule := "wasm\n"
			ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.handler(w, r, gotNumRequest)
				gotNumRequest++
			}))
			defer ts.Close()
			fetcher := NewHTTPFetcher()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			b, err := fetcher.Fetch(ctx, ts.URL, false)
			if c.wantNumRequest != gotNumRequest {
				t.Errorf("Wasm download request got %v, want %v", gotNumRequest, c.wantNumRequest)
			}
			if c.wantError != "" {
				if err == nil {
					t.Errorf("Wasm download got no error, want error `%v`", c.wantError)
				} else if c.wantError != err.Error() {
					t.Errorf("Wasm download got error `%v`, want error `%v`", err, c.wantError)
				}
			} else if string(b) != wantWasmModule {
				t.Errorf("downloaded wasm module got %v, want wasm", string(b))
			}
		})
	}
}
