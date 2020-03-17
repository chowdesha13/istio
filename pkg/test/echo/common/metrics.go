// Copyright 2020 Istio Authors
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

package common

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type EchoMetrics struct {
	HTTPRequests *prometheus.CounterVec
	GrpcRequests *prometheus.CounterVec
	TCPRequests  *prometheus.CounterVec
}

var (
	Metrics = &EchoMetrics{
		HTTPRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "istio_echo_http_requests_total",
			Help: "The number of http requests total",
		}, []string{"port"}),
		GrpcRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "istio_echo_grpc_requests_total",
			Help: "The number of http requests total",
		}, []string{"port"}),
		TCPRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Name: "istio_echo_tcp_requests_total",
			Help: "The number of http requests total",
		}, []string{"port"}),
	}
)
