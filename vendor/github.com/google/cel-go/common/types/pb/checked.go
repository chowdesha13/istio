// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pb

import (
	descpb "github.com/golang/protobuf/protoc-gen-go/descriptor"
	emptypb "github.com/golang/protobuf/ptypes/empty"
	structpb "github.com/golang/protobuf/ptypes/struct"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	// CheckedPrimitives map from proto field descriptor type to expr.Type.
	CheckedPrimitives = map[descpb.FieldDescriptorProto_Type]*exprpb.Type{
		descpb.FieldDescriptorProto_TYPE_BOOL:    checkedBool,
		descpb.FieldDescriptorProto_TYPE_BYTES:   checkedBytes,
		descpb.FieldDescriptorProto_TYPE_DOUBLE:  checkedDouble,
		descpb.FieldDescriptorProto_TYPE_FLOAT:   checkedDouble,
		descpb.FieldDescriptorProto_TYPE_INT32:   checkedInt,
		descpb.FieldDescriptorProto_TYPE_INT64:   checkedInt,
		descpb.FieldDescriptorProto_TYPE_SINT32:  checkedInt,
		descpb.FieldDescriptorProto_TYPE_SINT64:  checkedInt,
		descpb.FieldDescriptorProto_TYPE_UINT32:  checkedUint,
		descpb.FieldDescriptorProto_TYPE_UINT64:  checkedUint,
		descpb.FieldDescriptorProto_TYPE_FIXED32: checkedUint,
		descpb.FieldDescriptorProto_TYPE_FIXED64: checkedUint,
		descpb.FieldDescriptorProto_TYPE_STRING:  checkedString}

	// CheckedWellKnowns map from qualified proto type name to expr.Type for
	// well-known proto types.
	CheckedWellKnowns = map[string]*exprpb.Type{
		// Wrapper types.
		"google.protobuf.BoolValue":   checkedWrap(checkedBool),
		"google.protobuf.BytesValue":  checkedWrap(checkedBytes),
		"google.protobuf.DoubleValue": checkedWrap(checkedDouble),
		"google.protobuf.FloatValue":  checkedWrap(checkedDouble),
		"google.protobuf.Int64Value":  checkedWrap(checkedInt),
		"google.protobuf.Int32Value":  checkedWrap(checkedInt),
		"google.protobuf.UInt64Value": checkedWrap(checkedUint),
		"google.protobuf.UInt32Value": checkedWrap(checkedUint),
		"google.protobuf.StringValue": checkedWrap(checkedString),
		// Well-known types.
		"google.protobuf.Any":       checkedAny,
		"google.protobuf.Duration":  checkedDuration,
		"google.protobuf.Timestamp": checkedTimestamp,
		// Json types.
		"google.protobuf.ListValue": checkedListDyn,
		"google.protobuf.NullValue": checkedNull,
		"google.protobuf.Struct":    checkedMapStringDyn,
		"google.protobuf.Value":     checkedDyn,
	}

	// common types
	checkedDyn = &exprpb.Type{TypeKind: &exprpb.Type_Dyn{Dyn: &emptypb.Empty{}}}
	// Wrapper and primitive types.
	checkedBool   = checkedPrimitive(exprpb.Type_BOOL)
	checkedBytes  = checkedPrimitive(exprpb.Type_BYTES)
	checkedDouble = checkedPrimitive(exprpb.Type_DOUBLE)
	checkedInt    = checkedPrimitive(exprpb.Type_INT64)
	checkedString = checkedPrimitive(exprpb.Type_STRING)
	checkedUint   = checkedPrimitive(exprpb.Type_UINT64)
	// Well-known type equivalents.
	checkedAny       = checkedWellKnown(exprpb.Type_ANY)
	checkedDuration  = checkedWellKnown(exprpb.Type_DURATION)
	checkedTimestamp = checkedWellKnown(exprpb.Type_TIMESTAMP)
	// Json-based type equivalents.
	checkedNull = &exprpb.Type{
		TypeKind: &exprpb.Type_Null{
			Null: structpb.NullValue_NULL_VALUE}}
	checkedListDyn = &exprpb.Type{
		TypeKind: &exprpb.Type_ListType_{
			ListType: &exprpb.Type_ListType{ElemType: checkedDyn}}}
	checkedMapStringDyn = &exprpb.Type{
		TypeKind: &exprpb.Type_MapType_{
			MapType: &exprpb.Type_MapType{
				KeyType:   checkedString,
				ValueType: checkedDyn}}}
)
