// Copyright 2016 Google Inc.
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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/timestamp"
	"google.golang.org/grpc"

	bt "github.com/opentracing/basictracer-go"

	mixerpb "istio.io/api/mixer/v1"
	"istio.io/mixer/pkg/tracing"
)

type clientState struct {
	client     mixerpb.MixerClient
	connection *grpc.ClientConn
}

func createAPIClient(port string, enableTracing bool) (*clientState, error) {
	cs := clientState{}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	if enableTracing {
		opts = append(opts, grpc.WithStreamInterceptor(tracing.ClientInterceptor(bt.New(tracing.IORecorder(os.Stdout)))))
	}

	var err error
	if cs.connection, err = grpc.Dial(port, opts...); err != nil {
		return nil, err
	}

	cs.client = mixerpb.NewMixerClient(cs.connection)
	return &cs, nil
}

func deleteAPIClient(cs *clientState) {
	_ = cs.connection.Close()
	cs.client = nil
	cs.connection = nil
}

func parseString(s string) (interface{}, error)  { return s, nil }
func parseInt64(s string) (interface{}, error)   { return strconv.ParseInt(s, 10, 64) }
func parseFloat64(s string) (interface{}, error) { return strconv.ParseFloat(s, 64) }
func parseBool(s string) (interface{}, error)    { return strconv.ParseBool(s) }

func parseTime(s string) (interface{}, error) {
	time, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}

	return ptypes.TimestampProto(time)
}

func parseBytes(s string) (interface{}, error) {
	var bytes []uint8
	for _, seg := range strings.Split(s, ":") {
		b, err := strconv.ParseUint(seg, 16, 8)
		if err != nil {
			return nil, err
		}
		bytes = append(bytes, uint8(b))
	}
	return bytes, nil
}

type convertFn func(string) (interface{}, error)

func process(dictionary map[int32]string, s string, f convertFn) (map[int32]interface{}, error) {
	m := make(map[int32]interface{})
	if len(s) > 0 {
		for _, seg := range strings.Split(s, ",") {
			eq := strings.Index(seg, "=")
			if eq < 0 {
				return nil, fmt.Errorf("attribute value %v does not include an = sign", seg)
			}
			if eq == 0 {
				return nil, fmt.Errorf("attribute value %v does not contain a valid name", seg)
			}
			name := seg[0:eq]
			value := seg[eq+1:]

			// convert
			nv, err := f(value)
			if err != nil {
				return nil, err
			}

			// add to dictionary
			index := int32(len(dictionary))
			dictionary[index] = name

			// add to results
			m[index] = nv
		}
	}

	return m, nil
}

func parseAttributes(rootArgs *rootArgs) (*mixerpb.Attributes, error) {
	attrs := mixerpb.Attributes{}
	attrs.Dictionary = make(map[int32]string)
	attrs.StringAttributes = make(map[int32]string)
	attrs.Int64Attributes = make(map[int32]int64)
	attrs.DoubleAttributes = make(map[int32]float64)
	attrs.BoolAttributes = make(map[int32]bool)
	attrs.TimestampAttributes = make(map[int32]*timestamp.Timestamp)
	attrs.BytesAttributes = make(map[int32][]uint8)

	// the following boilerplate would be more succinct with generics...

	var m map[int32]interface{}
	var err error

	if m, err = process(attrs.Dictionary, rootArgs.stringAttributes, parseString); err != nil {
		return nil, err
	}
	for k, v := range m {
		attrs.StringAttributes[k] = v.(string)
	}

	if m, err = process(attrs.Dictionary, rootArgs.int64Attributes, parseInt64); err != nil {
		return nil, err
	}
	for k, v := range m {
		attrs.Int64Attributes[k] = v.(int64)
	}

	if m, err = process(attrs.Dictionary, rootArgs.doubleAttributes, parseFloat64); err != nil {
		return nil, err
	}
	for k, v := range m {
		attrs.DoubleAttributes[k] = v.(float64)
	}

	if m, err = process(attrs.Dictionary, rootArgs.boolAttributes, parseBool); err != nil {
		return nil, err
	}
	for k, v := range m {
		attrs.BoolAttributes[k] = v.(bool)
	}

	if m, err = process(attrs.Dictionary, rootArgs.timestampAttributes, parseTime); err != nil {
		return nil, err
	}
	for k, v := range m {
		attrs.TimestampAttributes[k] = v.(*timestamp.Timestamp)
	}

	if m, err = process(attrs.Dictionary, rootArgs.bytesAttributes, parseBytes); err != nil {
		return nil, err
	}
	for k, v := range m {
		attrs.BytesAttributes[k] = v.([]uint8)
	}

	if m, err = process(attrs.Dictionary, rootArgs.attributes, parseString); err != nil {
		return nil, err
	}
	for k, v := range m {
		s := v.(string)

		// auto-sense the type of attributes based on being to parse the value
		if val, err := parseInt64(s); err == nil {
			attrs.Int64Attributes[k] = val.(int64)
		} else if val, err := parseFloat64(s); err == nil {
			attrs.DoubleAttributes[k] = val.(float64)
		} else if val, err := parseBool(s); err == nil {
			attrs.BoolAttributes[k] = val.(bool)
		} else if val, err := parseTime(s); err == nil {
			attrs.TimestampAttributes[k] = val.(*timestamp.Timestamp)
		} else if val, err := parseBytes(s); err == nil {
			attrs.BytesAttributes[k] = val.([]uint8)
		} else {
			attrs.StringAttributes[k] = s
		}
	}

	return &attrs, nil
}
