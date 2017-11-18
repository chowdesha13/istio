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

package svcctrl

import (
	"encoding/json"
	"strconv"
	"time"

	rpc "github.com/googleapis/googleapis/google/rpc"
	sc "google.golang.org/api/servicecontrol/v1"

	"istio.io/istio/mixer/adapter/svcctrl/template/svcctrlreport"
)

const (
	endPointsLogName                  = "endpoints_log"
	endPointsLogSeverityInfo          = "INFO"
	endPointsLogSeverityError         = "ERROR"
	endPointsLogErrorCauseAuth        = "AUTH"
	endPointsLogErrorCauseApplication = "APPLICATION"
	endPointsMessage                  = "Method:"
)

type (
	consumerProjectIDResolver interface {
		// ResolveConsumerProjectID resolves consumer project ID from API key and operation.
		ResolveConsumerProjectID(rawAPIKey, OpName string) (string, error)
	}

	// Label generator function prototype
	generateLabelFunc func(instance *svcctrlreport.Instance) (string, bool)
	// Metric value generator function prototype
	generateMetricValueFunc func(instance *svcctrlreport.Instance) (*sc.MetricValue, error)

	// A definition for a metric
	metricDef struct {
		name           string
		valueGenerator generateMetricValueFunc
		labels         []string
	}

	// JSON payload in endpoint_log, see https://cloud.google.com/endpoints/docs/openapi/ref-endpoints-logs
	endPointsLog struct {
		URL                 string `json:"url,omitempty"`
		APIName             string `json:"api_name,omitempty"`
		APIVersion          string `json:"api_version,omitempty"`
		APIMethod           string `json:"api_method,omitempty"`
		APIKey              string `json:"api_key,omitempty"`
		HTTPMethod          string `json:"http_method,omitempty"`
		RequestSizeInBytes  int64  `json:"request_size_in_bytes,omitempty"`
		HTTPResponseCode    int64  `json:"http_response_code,omitempty"`
		ResponseSizeInBytes int64  `json:"response_size_in_bytes,omitempty"`
		RequestLatencyInMS  int64  `json:"request_latency_in_ms,omitempty"`
		Timestamp           string `json:"timestamp,omitempty"`
		Location            string `json:"location,omitempty"`
		LogMessage          string `json:"log_message,omitempty"`
		ErrorCause          string `json:"error_cause,omitempty"`
	}

	// reportBuilder builds metrics and logs from a single Google ServiceControl report template instance.
	reportBuilder struct {
		supportedMetrics []metricDef
		instance         *svcctrlreport.Instance
		resolver         consumerProjectIDResolver
		labelMap         map[string]string
	}
)

// A map from label to its generator function
var labelGeneratorMap = map[string]generateLabelFunc{
	"/consumer_id":         generateConsumerID,
	"/credential_id":       generateCredentialID,
	"/error_type":          generateErrorType,
	"/protocol":            generateProtocol,
	"/response_code":       generateResponseCode,
	"/response_code_class": generateResponseCodeClass,
	"/status_code":         generateStatusCode,
}

// Error types based on HTTP status code
var errorTypes = []string{
	"0xx", "1xx", "2xx", "3xx", "4xx",
	"5xx", "6xx", "7xx", "8xx", "9xx"}

// Well-known metric labels generator functions
func generateConsumerID(instance *svcctrlreport.Instance) (string, bool) {
	if instance.ApiKey == "" {
		return "", false
	}
	return generateConsumerIDFromAPIKey(instance.ApiKey), true
}

func generateCredentialID(instance *svcctrlreport.Instance) (string, bool) {
	if instance.ApiKey == "" {
		return "", false
	}
	return "apiKey:" + instance.ApiKey, true
}

func generateErrorType(instance *svcctrlreport.Instance) (string, bool) {
	if instance.ResponseCode < 400 || instance.ResponseCode >= 1000 {
		return "", false
	}
	return errorTypes[instance.ResponseCode/100], true
}

func generateProtocol(instance *svcctrlreport.Instance) (string, bool) {
	return instance.ApiProtocol, instance.ApiProtocol != ""
}

func generateResponseCode(instance *svcctrlreport.Instance) (string, bool) {
	return strconv.Itoa(int(instance.ResponseCode)), true
}

func generateResponseCodeClass(instance *svcctrlreport.Instance) (string, bool) {
	if instance.ResponseCode < 0 || instance.ResponseCode >= 1000 {
		return "", false
	}
	return errorTypes[instance.ResponseCode/100], true
}

func generateStatusCode(instance *svcctrlreport.Instance) (string, bool) {
	rpcCode := toRPCCode(int(instance.ResponseCode))
	return strconv.Itoa(int(rpcCode)), true
}

// Helpers to generate metric value.
func generateRequestCount(inst *svcctrlreport.Instance) (*sc.MetricValue, error) {
	return &sc.MetricValue{
		StartTime:  inst.RequestTime.UTC().Format(time.RFC3339Nano),
		EndTime:    inst.ResponseTime.UTC().Format(time.RFC3339Nano),
		Int64Value: getInt64Address(1),
	}, nil
}

func generateErrorCount(instance *svcctrlreport.Instance) (*sc.MetricValue, error) {
	// Skip if not an error
	if instance.ResponseCode < 300 {
		return nil, nil
	}
	return generateRequestCount(instance)
}

func generateBackendLatencies(instance *svcctrlreport.Instance) (*sc.MetricValue, error) {
	builder, err := newDistValueBuilder(timeOption)
	if err != nil {
		return nil, nil
	}

	// latency in second
	latency := float64(instance.ResponseLatency/time.Microsecond) / 1000000.0
	builder.addSample(latency)
	return &sc.MetricValue{
		StartTime:         instance.RequestTime.UTC().Format(time.RFC3339Nano),
		EndTime:           instance.ResponseTime.UTC().Format(time.RFC3339Nano),
		DistributionValue: builder.build(),
	}, nil
}

// Helpers to generate EndPoints log entry
func generateLogSeverity(httpCode int) string {
	if httpCode >= 400 {
		return endPointsLogSeverityError
	}
	return endPointsLogSeverityInfo
}

func generateLogMessage(instance *svcctrlreport.Instance) string {
	if instance.ApiOperation == "" {
		return ""
	}
	return endPointsMessage + instance.ApiOperation
}

func generateLogErrorCause(instance *svcctrlreport.Instance) string {
	if instance.ResponseCode < 400 {
		return ""
	} else if toRPCCode(int(instance.ResponseCode)) == rpc.PERMISSION_DENIED {
		return endPointsLogErrorCauseAuth
	}
	return endPointsLogErrorCauseApplication
}

/////// reportBuilder methods ///////
func (b *reportBuilder) build(op *sc.Operation) {
	b.addMetricValues(op)
	b.addLogEntry(op)
}

// addMetricValues adds metric value sets to operation
// TODO(manlinl): if /credential_id label is missing, don't include consumer metrics.
func (b *reportBuilder) addMetricValues(op *sc.Operation) {
	if b.supportedMetrics == nil {
		return
	}

	op.Labels = b.generateAPIResourceLables()
	metricValueSets := make([]*sc.MetricValueSet, 0, len(b.supportedMetrics))
	for _, metric := range b.supportedMetrics {
		metricSet := new(sc.MetricValueSet)
		metricSet.MetricName = metric.name
		metricValue, innerErr := metric.valueGenerator(b.instance)
		if innerErr != nil {
			continue
		}

		if len(metric.labels) > 0 {
			metricValue.Labels = make(map[string]string)
			for _, label := range metric.labels {
				if labelValue, ok := b.getLabelValue(label); ok {
					metricValue.Labels[label] = labelValue
				}
			}
		}
		metricSet.MetricValues = []*sc.MetricValue{metricValue}
		metricValueSets = append(metricValueSets, metricSet)
	}

	op.MetricValueSets = metricValueSets
}

func (b *reportBuilder) getLabelValue(label string) (string, bool) {
	if value, found := b.labelMap[label]; found {
		return value, true
	}

	labelGenerator, found := labelGeneratorMap[label]
	if !found {
		return "", false
	}

	labelValue, ok := labelGenerator(b.instance)
	if ok {
		b.labelMap[label] = labelValue
	}
	return labelValue, ok
}

// addLogEntry adds Endpoint log entry to operation
func (b *reportBuilder) addLogEntry(op *sc.Operation) {
	payload, err := b.generateLogJSONPayload()
	if err != nil {
		return
	}

	log := &sc.LogEntry{
		Name:          endPointsLogName,
		Timestamp:     b.instance.RequestTime.UTC().Format(time.RFC3339Nano),
		Severity:      generateLogSeverity(int(b.instance.ResponseCode)),
		StructPayload: payload,
	}

	if op.LogEntries == nil {
		op.LogEntries = []*sc.LogEntry{log}
	} else {
		op.LogEntries = append(op.LogEntries, log)
	}
}

func (b *reportBuilder) generateLogJSONPayload() ([]byte, error) {
	payload := endPointsLog{}
	payload.APIKey = b.instance.ApiKey
	payload.APIName = b.instance.ApiService
	payload.APIMethod = b.instance.ApiOperation
	payload.HTTPMethod = b.instance.RequestMethod
	payload.RequestSizeInBytes = b.instance.RequestBytes
	payload.HTTPResponseCode = b.instance.ResponseCode
	payload.RequestLatencyInMS = int64(b.instance.ResponseLatency / time.Millisecond)
	payload.Timestamp = b.instance.RequestTime.UTC().Format(time.RFC3339Nano)
	payload.Location = "global"
	payload.LogMessage = generateLogMessage(b.instance)
	payload.ErrorCause = generateLogErrorCause(b.instance)
	return json.Marshal(payload)
}

func (b *reportBuilder) generateAPIResourceLables() map[string]string {
	labels := make(map[string]string)
	if b.instance.ApiKey != "" {
		consumerID := generateConsumerIDFromAPIKey(b.instance.ApiKey)
		if b.instance.ApiOperation != "" {
			consumerProjID, err := b.resolver.ResolveConsumerProjectID(consumerID, b.instance.ApiOperation)
			if err == nil {
				labels["serviceruntime.googleapis.com/consumer_project"] = consumerProjID
			}
		}
	}

	if b.instance.ApiVersion != "" {
		labels["serviceruntime.googleapis.com/api_version"] = b.instance.ApiVersion
	}

	if b.instance.ApiOperation != "" {
		labels["serviceruntime.googleapis.com/api_method"] = b.instance.ApiOperation
	}

	// TODO(manlinl): Read location from GCE metadata server.
	labels["cloud.googleapis.com/location"] = "global"
	return labels
}
