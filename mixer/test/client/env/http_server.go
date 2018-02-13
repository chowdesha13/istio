// Copyright 2017 Istio Authors. All Rights Reserved.
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

package env

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

// If HTTP header has non empty FailHeader,
// HTTP server will fail the request with 400 with FailBody in the response body.
const (
	FailHeader = "x-istio-backend-fail"
	FailBody   = "Bad request from backend."
)

const publicKey = `
{
    "keys": [
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
            "kty": "RSA",
            "n": "` +
	"0YWnm_eplO9BFtXszMRQNL5UtZ8HJdTH2jK7vjs4XdLkPW7YBkkm_2xNgcaVpkW0VT2l4mU3KftR-6" +
	"s3Oa5Rnz5BrWEUkCTVVolR7VYksfqIB2I_x5yZHdOiomMTcm3DheUUCgbJRv5OKRnNqszA4xHn3tA3" +
	"Ry8VO3X7BgKZYAUh9fyZTFLlkeAh0-bLK5zvqCmKW5QgDIXSxUTJxPjZCgfx1vmAfGqaJb-nvmrORX" +
	"Q6L284c73DUL7mnt6wj3H6tVqPKA27j56N0TB1Hfx4ja6Slr8S4EB3F1luYhATa1PKUSH8mYDW11Ho" +
	"lzZmTQpRoLV8ZoHbHEaTfqX_aYahIw" +
	`",
            "use": "sig"
        },
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
            "kty": "RSA",
            "n": "` +
	"qDi7Tx4DhNvPQsl1ofxxc2ePQFcs-L0mXYo6TGS64CY_2WmOtvYlcLNZjhuddZVV2X88m0MfwaSA16w" +
	"E-RiKM9hqo5EY8BPXj57CMiYAyiHuQPp1yayjMgoE1P2jvp4eqF-BTillGJt5W5RuXti9uqfMtCQdag" +
	"B8EC3MNRuU_KdeLgBy3lS3oo4LOYd-74kRBVZbk2wnmmb7IhP9OoLc1-7-9qU1uhpDxmE6JwBau0mDS" +
	"wMnYDS4G_ML17dC-ZDtLd1i24STUw39KH0pcSdfFbL2NtEZdNeam1DDdk0iUtJSPZliUHJBI_pj8M-2" +
	"Mn_oA8jBuI8YKwBqYkZCN1I95Q" +
	`",
            "use": "sig"
        }
    ]
}
`

// HTTPServer stores data for a HTTP server.
type HTTPServer struct {
	port uint16
	lis  net.Listener
}

func pubkeyHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%v", publicKey)
}

func regularResponseHandler(w http.ResponseWriter, r *http.Request) {
	handler(w, r, false)
}

func slowResponseHandler(w http.ResponseWriter, r *http.Request) {
	handler(w, r, true)
}

// handler handles a request and sends response. If slowResponse is true, then sleeps 3 second and
// sends response.
func handler(w http.ResponseWriter, r *http.Request, slowResponse bool) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Fail if there is such header.
	if r.Header.Get(FailHeader) != "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(FailBody))
		return
	}

	// echo back the Content-Type and Content-Length in the response
	for _, k := range []string{"Content-Type", "Content-Length"} {
		if v := r.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(http.StatusOK)
	if slowResponse {
		time.Sleep(3 * time.Second)
		_, _ = w.Write(body)
	} else {
		_, _ = w.Write(body)
	}
}

// NewHTTPServer creates a new HTTP server.
func NewHTTPServer(port uint16) (*HTTPServer, error) {
	log.Printf("Http server listening on port %v\n", port)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	return &HTTPServer{
		port: port,
		lis:  lis,
	}, nil
}

// Start starts the server
func (s *HTTPServer) Start() {
	go func() {
		http.HandleFunc("/", regularResponseHandler)
		http.HandleFunc("/slowresponse", slowResponseHandler)
		http.HandleFunc("/pubkey", pubkeyHandler)
		_ = http.Serve(s.lis, nil)
	}()

	url := fmt.Sprintf("http://localhost:%v/echo", s.port)
	WaitForHTTPServer(url)
}

// Stop shutdown the server
func (s *HTTPServer) Stop() {
	log.Printf("Close HTTP server\n")
	_ = s.lis.Close()
	log.Printf("Close HTTP server -- Done\n")
}
