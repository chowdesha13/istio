// Copyright (c) 2017 Uber Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jaeger

import (
	"time"

	"github.com/opentracing/opentracing-go"

	j "github.com/uber/jaeger-client-go/thrift-gen/jaeger"
	"github.com/uber/jaeger-client-go/utils"
)

// BuildJaegerThrift builds jaeger span based on internal span.
func BuildJaegerThrift(span *Span) *j.Span {
	startTime := utils.TimeToMicrosecondsSinceEpochInt64(span.startTime)
	duration := span.duration.Nanoseconds() / int64(time.Microsecond)
	jaegerSpan := &j.Span{
		TraceIdLow:    int64(span.context.traceID.Low),
		TraceIdHigh:   int64(span.context.traceID.High),
		SpanId:        int64(span.context.spanID),
		ParentSpanId:  int64(span.context.parentID),
		OperationName: span.operationName,
		Flags:         int32(span.context.flags),
		StartTime:     startTime,
		Duration:      duration,
		Tags:          buildTags(span.tags),
		Logs:          buildLogs(span.logs),
		References:    buildReferences(span.references),
	}
	return jaegerSpan
}

// BuildJaegerProcessThrift creates a thrift Process type.
func BuildJaegerProcessThrift(span *Span) *j.Process {
	return buildJaegerProcessThrift(span.tracer)
}

func buildJaegerProcessThrift(tracer *Tracer) *j.Process {
	process := &j.Process{
		ServiceName: tracer.serviceName,
		Tags:        buildTags(tracer.tags),
	}
	return process
}

func buildTags(tags []Tag) []*j.Tag {
	jTags := make([]*j.Tag, 0, len(tags))
	for _, tag := range tags {
		jTag := buildTag(&tag)
		jTags = append(jTags, jTag)
	}
	return jTags
}

func buildLogs(logs []opentracing.LogRecord) []*j.Log {
	jLogs := make([]*j.Log, 0, len(logs))
	for _, log := range logs {
		jLog := &j.Log{
			Timestamp: utils.TimeToMicrosecondsSinceEpochInt64(log.Timestamp),
			Fields:    ConvertLogsToJaegerTags(log.Fields),
		}
		jLogs = append(jLogs, jLog)
	}
	return jLogs
}

func buildTag(tag *Tag) *j.Tag {
	jTag := &j.Tag{Key: tag.key}
	switch value := tag.value.(type) {
	case string:
		vStr := truncateString(value)
		jTag.VStr = &vStr
		jTag.VType = j.TagType_STRING
	case []byte:
		if len(value) > maxAnnotationLength {
			value = value[:maxAnnotationLength]
		}
		jTag.VBinary = value
		jTag.VType = j.TagType_BINARY
	case int:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case uint:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case int8:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case uint8:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case int16:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case uint16:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case int32:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case uint32:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case int64:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case uint64:
		vLong := int64(value)
		jTag.VLong = &vLong
		jTag.VType = j.TagType_LONG
	case float32:
		vDouble := float64(value)
		jTag.VDouble = &vDouble
		jTag.VType = j.TagType_DOUBLE
	case float64:
		vDouble := float64(value)
		jTag.VDouble = &vDouble
		jTag.VType = j.TagType_DOUBLE
	case bool:
		vBool := value
		jTag.VBool = &vBool
		jTag.VType = j.TagType_BOOL
	default:
		vStr := truncateString(stringify(value))
		jTag.VStr = &vStr
		jTag.VType = j.TagType_STRING
	}
	return jTag
}

func buildReferences(references []Reference) []*j.SpanRef {
	retMe := make([]*j.SpanRef, 0, len(references))
	for _, ref := range references {
		if ref.Type == opentracing.ChildOfRef {
			retMe = append(retMe, spanRef(ref.Context, j.SpanRefType_CHILD_OF))
		} else if ref.Type == opentracing.FollowsFromRef {
			retMe = append(retMe, spanRef(ref.Context, j.SpanRefType_FOLLOWS_FROM))
		}
	}
	return retMe
}

func spanRef(ctx SpanContext, refType j.SpanRefType) *j.SpanRef {
	return &j.SpanRef{
		RefType:     refType,
		TraceIdLow:  int64(ctx.traceID.Low),
		TraceIdHigh: int64(ctx.traceID.High),
		SpanId:      int64(ctx.spanID),
	}
}
