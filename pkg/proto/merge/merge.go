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

package merge

/*
 CODE Copied and modified from https://github.com/kumahq/kuma/blob/master/pkg/util/proto/google_proto.go
 because of: https://github.com/golang/protobuf/issues/1359

  Copyright 2019 The Go Authors. All rights reserved.
  Use of this source code is governed by a BSD-style
  license that can be found in the LICENSE file.
*/

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/durationpb"
)

type (
	MergeFunction func(dst, src protoreflect.Message)

	CloneFunction func(src protoreflect.Message) bool

	mergeOptions struct {
		customMergeFn map[protoreflect.FullName]MergeFunction
		customCloneFn map[protoreflect.FullName]CloneFunction
	}
)
type OptionFn func(options mergeOptions) mergeOptions

func MergeFunctionOptionFn(name protoreflect.FullName, function MergeFunction) OptionFn {
	return func(options mergeOptions) mergeOptions {
		options.customMergeFn[name] = function
		return options
	}
}

func CloneFunctionOptionFn(name protoreflect.FullName, function CloneFunction) OptionFn {
	return func(options mergeOptions) mergeOptions {
		options.customCloneFn[name] = function
		return options
	}
}

// ReplaceMergeFn instead of merging all subfields one by one, takes src and set it to dest
var ReplaceMergeFn MergeFunction = func(dst, src protoreflect.Message) {
	dst.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		dst.Clear(fd)
		return true
	})
	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		dst.Set(fd, v)
		return true
	})
}

var options = []OptionFn{
	// Workaround https://github.com/golang/protobuf/issues/1359, merge duration properly
	MergeFunctionOptionFn((&durationpb.Duration{}).ProtoReflect().Descriptor().FullName(), ReplaceMergeFn),
}

// Merge does a proto merge by applying any custom merge functions.
func Merge(dst, src proto.Message) proto.Message {
	return merge(dst, src, options...)
}

// MustClone registers a clone function that tells whether we should clone the message before merging.
// This is used in cases where we cache proto messages that can be modified via Envoy filters.
func MustClone(msg proto.Message, cloneFn CloneFunction) proto.Message {
	copied := make([]OptionFn, 0)
	copied = append(copied, options...)
	copied = append(copied, CloneFunctionOptionFn(msg.ProtoReflect().Descriptor().FullName(), cloneFn))
	options = copied
	return msg
}

// Merge Code of proto.Merge with modifications to support custom types
func merge(dst, src proto.Message, opts ...OptionFn) proto.Message {
	mo := mergeOptions{
		customMergeFn: map[protoreflect.FullName]MergeFunction{},
		customCloneFn: map[protoreflect.FullName]CloneFunction{},
	}
	for _, opt := range opts {
		mo = opt(mo)
	}
	dstMsg, srcMsg := dst.ProtoReflect(), src.ProtoReflect()
	if dstMsg.Descriptor() != srcMsg.Descriptor() {
		if got, want := dstMsg.Descriptor().FullName(), srcMsg.Descriptor().FullName(); got != want {
			panic(fmt.Sprintf("descriptor mismatch: %v != %v", got, want))
		}
		panic("descriptor mismatch")
	}
	return mo.mergeMessage(dstMsg, srcMsg)
}

func (o mergeOptions) mergeMessage(dst, src protoreflect.Message) proto.Message {
	// The regular proto.mergeMessage would have a fast path method option here.
	// As we want to have exceptions we always use the slow path.
	if !dst.IsValid() {
		panic(fmt.Sprintf("cannot merge into invalid %v message", dst.Descriptor().FullName()))
	}

	// Check if we need to clone before merging the main message.
	if cloneFn, exists := o.customCloneFn[src.Descriptor().FullName()]; exists && cloneFn(dst) {
		dst = proto.Clone(dst.Interface()).ProtoReflect()
	}

	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			o.mergeList(dst.Mutable(fd).List(), v.List(), fd)
		case fd.IsMap():
			o.mergeMap(dst.Mutable(fd).Map(), v.Map(), fd.MapValue())
		case fd.Message() != nil:
			// Check if we need to clone before merging this message.
			if cloneFn, exists := o.customCloneFn[fd.Message().FullName()]; exists && cloneFn(dst.Mutable(fd).Message()) {
				dst = proto.Clone(dst.Mutable(fd).Message().Interface()).ProtoReflect()
			}
			mergeFn, exists := o.customMergeFn[fd.Message().FullName()]
			if exists {
				mergeFn(dst.Mutable(fd).Message(), v.Message())
			} else {
				o.mergeMessage(dst.Mutable(fd).Message(), v.Message())
			}
		case fd.Kind() == protoreflect.BytesKind:
			dst.Set(fd, o.cloneBytes(v))
		default:
			dst.Set(fd, v)
		}
		return true
	})

	if len(src.GetUnknown()) > 0 {
		dst.SetUnknown(append(dst.GetUnknown(), src.GetUnknown()...))
	}
	return dst.Interface()
}

func (o mergeOptions) mergeList(dst, src protoreflect.List, fd protoreflect.FieldDescriptor) {
	// Merge semantics appends to the end of the existing list.
	for i, n := 0, src.Len(); i < n; i++ {
		switch v := src.Get(i); {
		case fd.Message() != nil:
			dstv := dst.NewElement()
			o.mergeMessage(dstv.Message(), v.Message())
			dst.Append(dstv)
		case fd.Kind() == protoreflect.BytesKind:
			dst.Append(o.cloneBytes(v))
		default:
			dst.Append(v)
		}
	}
}

func (o mergeOptions) mergeMap(dst, src protoreflect.Map, fd protoreflect.FieldDescriptor) {
	// Merge semantics replaces, rather than merges into existing entries.
	src.Range(func(k protoreflect.MapKey, v protoreflect.Value) bool {
		switch {
		case fd.Message() != nil:
			dstv := dst.NewValue()
			o.mergeMessage(dstv.Message(), v.Message())
			dst.Set(k, dstv)
		case fd.Kind() == protoreflect.BytesKind:
			dst.Set(k, o.cloneBytes(v))
		default:
			dst.Set(k, v)
		}
		return true
	})
}

func (o mergeOptions) cloneBytes(v protoreflect.Value) protoreflect.Value {
	return protoreflect.ValueOfBytes(append([]byte{}, v.Bytes()...))
}
