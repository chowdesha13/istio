// Code generated by protoc-gen-go. DO NOT EDIT.
// source: google/spanner/v1/result_set.proto

package spanner // import "google.golang.org/genproto/googleapis/spanner/v1"

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _struct "github.com/golang/protobuf/ptypes/struct"
import _ "google.golang.org/genproto/googleapis/api/annotations"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Results from [Read][google.spanner.v1.Spanner.Read] or
// [ExecuteSql][google.spanner.v1.Spanner.ExecuteSql].
type ResultSet struct {
	// Metadata about the result set, such as row type information.
	Metadata *ResultSetMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// Each element in `rows` is a row whose format is defined by
	// [metadata.row_type][google.spanner.v1.ResultSetMetadata.row_type]. The ith
	// element in each row matches the ith field in
	// [metadata.row_type][google.spanner.v1.ResultSetMetadata.row_type]. Elements
	// are encoded based on type as described [here][google.spanner.v1.TypeCode].
	Rows []*_struct.ListValue `protobuf:"bytes,2,rep,name=rows,proto3" json:"rows,omitempty"`
	// Query plan and execution statistics for the SQL statement that
	// produced this result set. These can be requested by setting
	// [ExecuteSqlRequest.query_mode][google.spanner.v1.ExecuteSqlRequest.query_mode].
	// DML statements always produce stats containing the number of rows
	// modified, unless executed using the
	// [ExecuteSqlRequest.QueryMode.PLAN][google.spanner.v1.ExecuteSqlRequest.QueryMode.PLAN]
	// [ExecuteSqlRequest.query_mode][google.spanner.v1.ExecuteSqlRequest.query_mode].
	// Other fields may or may not be populated, based on the
	// [ExecuteSqlRequest.query_mode][google.spanner.v1.ExecuteSqlRequest.query_mode].
	Stats                *ResultSetStats `protobuf:"bytes,3,opt,name=stats,proto3" json:"stats,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *ResultSet) Reset()         { *m = ResultSet{} }
func (m *ResultSet) String() string { return proto.CompactTextString(m) }
func (*ResultSet) ProtoMessage()    {}
func (*ResultSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_result_set_d916e3d6bffb4227, []int{0}
}
func (m *ResultSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResultSet.Unmarshal(m, b)
}
func (m *ResultSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResultSet.Marshal(b, m, deterministic)
}
func (dst *ResultSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResultSet.Merge(dst, src)
}
func (m *ResultSet) XXX_Size() int {
	return xxx_messageInfo_ResultSet.Size(m)
}
func (m *ResultSet) XXX_DiscardUnknown() {
	xxx_messageInfo_ResultSet.DiscardUnknown(m)
}

var xxx_messageInfo_ResultSet proto.InternalMessageInfo

func (m *ResultSet) GetMetadata() *ResultSetMetadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *ResultSet) GetRows() []*_struct.ListValue {
	if m != nil {
		return m.Rows
	}
	return nil
}

func (m *ResultSet) GetStats() *ResultSetStats {
	if m != nil {
		return m.Stats
	}
	return nil
}

// Partial results from a streaming read or SQL query. Streaming reads and
// SQL queries better tolerate large result sets, large rows, and large
// values, but are a little trickier to consume.
type PartialResultSet struct {
	// Metadata about the result set, such as row type information.
	// Only present in the first response.
	Metadata *ResultSetMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// A streamed result set consists of a stream of values, which might
	// be split into many `PartialResultSet` messages to accommodate
	// large rows and/or large values. Every N complete values defines a
	// row, where N is equal to the number of entries in
	// [metadata.row_type.fields][google.spanner.v1.StructType.fields].
	//
	// Most values are encoded based on type as described
	// [here][google.spanner.v1.TypeCode].
	//
	// It is possible that the last value in values is "chunked",
	// meaning that the rest of the value is sent in subsequent
	// `PartialResultSet`(s). This is denoted by the
	// [chunked_value][google.spanner.v1.PartialResultSet.chunked_value] field.
	// Two or more chunked values can be merged to form a complete value as
	// follows:
	//
	//   * `bool/number/null`: cannot be chunked
	//   * `string`: concatenate the strings
	//   * `list`: concatenate the lists. If the last element in a list is a
	//     `string`, `list`, or `object`, merge it with the first element in
	//     the next list by applying these rules recursively.
	//   * `object`: concatenate the (field name, field value) pairs. If a
	//     field name is duplicated, then apply these rules recursively
	//     to merge the field values.
	//
	// Some examples of merging:
	//
	//     # Strings are concatenated.
	//     "foo", "bar" => "foobar"
	//
	//     # Lists of non-strings are concatenated.
	//     [2, 3], [4] => [2, 3, 4]
	//
	//     # Lists are concatenated, but the last and first elements are merged
	//     # because they are strings.
	//     ["a", "b"], ["c", "d"] => ["a", "bc", "d"]
	//
	//     # Lists are concatenated, but the last and first elements are merged
	//     # because they are lists. Recursively, the last and first elements
	//     # of the inner lists are merged because they are strings.
	//     ["a", ["b", "c"]], [["d"], "e"] => ["a", ["b", "cd"], "e"]
	//
	//     # Non-overlapping object fields are combined.
	//     {"a": "1"}, {"b": "2"} => {"a": "1", "b": 2"}
	//
	//     # Overlapping object fields are merged.
	//     {"a": "1"}, {"a": "2"} => {"a": "12"}
	//
	//     # Examples of merging objects containing lists of strings.
	//     {"a": ["1"]}, {"a": ["2"]} => {"a": ["12"]}
	//
	// For a more complete example, suppose a streaming SQL query is
	// yielding a result set whose rows contain a single string
	// field. The following `PartialResultSet`s might be yielded:
	//
	//     {
	//       "metadata": { ... }
	//       "values": ["Hello", "W"]
	//       "chunked_value": true
	//       "resume_token": "Af65..."
	//     }
	//     {
	//       "values": ["orl"]
	//       "chunked_value": true
	//       "resume_token": "Bqp2..."
	//     }
	//     {
	//       "values": ["d"]
	//       "resume_token": "Zx1B..."
	//     }
	//
	// This sequence of `PartialResultSet`s encodes two rows, one
	// containing the field value `"Hello"`, and a second containing the
	// field value `"World" = "W" + "orl" + "d"`.
	Values []*_struct.Value `protobuf:"bytes,2,rep,name=values,proto3" json:"values,omitempty"`
	// If true, then the final value in
	// [values][google.spanner.v1.PartialResultSet.values] is chunked, and must be
	// combined with more values from subsequent `PartialResultSet`s to obtain a
	// complete field value.
	ChunkedValue bool `protobuf:"varint,3,opt,name=chunked_value,json=chunkedValue,proto3" json:"chunked_value,omitempty"`
	// Streaming calls might be interrupted for a variety of reasons, such
	// as TCP connection loss. If this occurs, the stream of results can
	// be resumed by re-sending the original request and including
	// `resume_token`. Note that executing any other transaction in the
	// same session invalidates the token.
	ResumeToken []byte `protobuf:"bytes,4,opt,name=resume_token,json=resumeToken,proto3" json:"resume_token,omitempty"`
	// Query plan and execution statistics for the statement that produced this
	// streaming result set. These can be requested by setting
	// [ExecuteSqlRequest.query_mode][google.spanner.v1.ExecuteSqlRequest.query_mode]
	// and are sent only once with the last response in the stream. This field
	// will also be present in the last response for DML statements.
	Stats                *ResultSetStats `protobuf:"bytes,5,opt,name=stats,proto3" json:"stats,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *PartialResultSet) Reset()         { *m = PartialResultSet{} }
func (m *PartialResultSet) String() string { return proto.CompactTextString(m) }
func (*PartialResultSet) ProtoMessage()    {}
func (*PartialResultSet) Descriptor() ([]byte, []int) {
	return fileDescriptor_result_set_d916e3d6bffb4227, []int{1}
}
func (m *PartialResultSet) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PartialResultSet.Unmarshal(m, b)
}
func (m *PartialResultSet) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PartialResultSet.Marshal(b, m, deterministic)
}
func (dst *PartialResultSet) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PartialResultSet.Merge(dst, src)
}
func (m *PartialResultSet) XXX_Size() int {
	return xxx_messageInfo_PartialResultSet.Size(m)
}
func (m *PartialResultSet) XXX_DiscardUnknown() {
	xxx_messageInfo_PartialResultSet.DiscardUnknown(m)
}

var xxx_messageInfo_PartialResultSet proto.InternalMessageInfo

func (m *PartialResultSet) GetMetadata() *ResultSetMetadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *PartialResultSet) GetValues() []*_struct.Value {
	if m != nil {
		return m.Values
	}
	return nil
}

func (m *PartialResultSet) GetChunkedValue() bool {
	if m != nil {
		return m.ChunkedValue
	}
	return false
}

func (m *PartialResultSet) GetResumeToken() []byte {
	if m != nil {
		return m.ResumeToken
	}
	return nil
}

func (m *PartialResultSet) GetStats() *ResultSetStats {
	if m != nil {
		return m.Stats
	}
	return nil
}

// Metadata about a [ResultSet][google.spanner.v1.ResultSet] or
// [PartialResultSet][google.spanner.v1.PartialResultSet].
type ResultSetMetadata struct {
	// Indicates the field names and types for the rows in the result
	// set.  For example, a SQL query like `"SELECT UserId, UserName FROM
	// Users"` could return a `row_type` value like:
	//
	//     "fields": [
	//       { "name": "UserId", "type": { "code": "INT64" } },
	//       { "name": "UserName", "type": { "code": "STRING" } },
	//     ]
	RowType *StructType `protobuf:"bytes,1,opt,name=row_type,json=rowType,proto3" json:"row_type,omitempty"`
	// If the read or SQL query began a transaction as a side-effect, the
	// information about the new transaction is yielded here.
	Transaction          *Transaction `protobuf:"bytes,2,opt,name=transaction,proto3" json:"transaction,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *ResultSetMetadata) Reset()         { *m = ResultSetMetadata{} }
func (m *ResultSetMetadata) String() string { return proto.CompactTextString(m) }
func (*ResultSetMetadata) ProtoMessage()    {}
func (*ResultSetMetadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_result_set_d916e3d6bffb4227, []int{2}
}
func (m *ResultSetMetadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResultSetMetadata.Unmarshal(m, b)
}
func (m *ResultSetMetadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResultSetMetadata.Marshal(b, m, deterministic)
}
func (dst *ResultSetMetadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResultSetMetadata.Merge(dst, src)
}
func (m *ResultSetMetadata) XXX_Size() int {
	return xxx_messageInfo_ResultSetMetadata.Size(m)
}
func (m *ResultSetMetadata) XXX_DiscardUnknown() {
	xxx_messageInfo_ResultSetMetadata.DiscardUnknown(m)
}

var xxx_messageInfo_ResultSetMetadata proto.InternalMessageInfo

func (m *ResultSetMetadata) GetRowType() *StructType {
	if m != nil {
		return m.RowType
	}
	return nil
}

func (m *ResultSetMetadata) GetTransaction() *Transaction {
	if m != nil {
		return m.Transaction
	}
	return nil
}

// Additional statistics about a [ResultSet][google.spanner.v1.ResultSet] or
// [PartialResultSet][google.spanner.v1.PartialResultSet].
type ResultSetStats struct {
	// [QueryPlan][google.spanner.v1.QueryPlan] for the query associated with this
	// result.
	QueryPlan *QueryPlan `protobuf:"bytes,1,opt,name=query_plan,json=queryPlan,proto3" json:"query_plan,omitempty"`
	// Aggregated statistics from the execution of the query. Only present when
	// the query is profiled. For example, a query could return the statistics as
	// follows:
	//
	//     {
	//       "rows_returned": "3",
	//       "elapsed_time": "1.22 secs",
	//       "cpu_time": "1.19 secs"
	//     }
	QueryStats *_struct.Struct `protobuf:"bytes,2,opt,name=query_stats,json=queryStats,proto3" json:"query_stats,omitempty"`
	// The number of rows modified by the DML statement.
	//
	// Types that are valid to be assigned to RowCount:
	//	*ResultSetStats_RowCountExact
	//	*ResultSetStats_RowCountLowerBound
	RowCount             isResultSetStats_RowCount `protobuf_oneof:"row_count"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *ResultSetStats) Reset()         { *m = ResultSetStats{} }
func (m *ResultSetStats) String() string { return proto.CompactTextString(m) }
func (*ResultSetStats) ProtoMessage()    {}
func (*ResultSetStats) Descriptor() ([]byte, []int) {
	return fileDescriptor_result_set_d916e3d6bffb4227, []int{3}
}
func (m *ResultSetStats) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ResultSetStats.Unmarshal(m, b)
}
func (m *ResultSetStats) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ResultSetStats.Marshal(b, m, deterministic)
}
func (dst *ResultSetStats) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ResultSetStats.Merge(dst, src)
}
func (m *ResultSetStats) XXX_Size() int {
	return xxx_messageInfo_ResultSetStats.Size(m)
}
func (m *ResultSetStats) XXX_DiscardUnknown() {
	xxx_messageInfo_ResultSetStats.DiscardUnknown(m)
}

var xxx_messageInfo_ResultSetStats proto.InternalMessageInfo

func (m *ResultSetStats) GetQueryPlan() *QueryPlan {
	if m != nil {
		return m.QueryPlan
	}
	return nil
}

func (m *ResultSetStats) GetQueryStats() *_struct.Struct {
	if m != nil {
		return m.QueryStats
	}
	return nil
}

type isResultSetStats_RowCount interface {
	isResultSetStats_RowCount()
}

type ResultSetStats_RowCountExact struct {
	RowCountExact int64 `protobuf:"varint,3,opt,name=row_count_exact,json=rowCountExact,proto3,oneof"`
}

type ResultSetStats_RowCountLowerBound struct {
	RowCountLowerBound int64 `protobuf:"varint,4,opt,name=row_count_lower_bound,json=rowCountLowerBound,proto3,oneof"`
}

func (*ResultSetStats_RowCountExact) isResultSetStats_RowCount() {}

func (*ResultSetStats_RowCountLowerBound) isResultSetStats_RowCount() {}

func (m *ResultSetStats) GetRowCount() isResultSetStats_RowCount {
	if m != nil {
		return m.RowCount
	}
	return nil
}

func (m *ResultSetStats) GetRowCountExact() int64 {
	if x, ok := m.GetRowCount().(*ResultSetStats_RowCountExact); ok {
		return x.RowCountExact
	}
	return 0
}

func (m *ResultSetStats) GetRowCountLowerBound() int64 {
	if x, ok := m.GetRowCount().(*ResultSetStats_RowCountLowerBound); ok {
		return x.RowCountLowerBound
	}
	return 0
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*ResultSetStats) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _ResultSetStats_OneofMarshaler, _ResultSetStats_OneofUnmarshaler, _ResultSetStats_OneofSizer, []interface{}{
		(*ResultSetStats_RowCountExact)(nil),
		(*ResultSetStats_RowCountLowerBound)(nil),
	}
}

func _ResultSetStats_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*ResultSetStats)
	// row_count
	switch x := m.RowCount.(type) {
	case *ResultSetStats_RowCountExact:
		b.EncodeVarint(3<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.RowCountExact))
	case *ResultSetStats_RowCountLowerBound:
		b.EncodeVarint(4<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.RowCountLowerBound))
	case nil:
	default:
		return fmt.Errorf("ResultSetStats.RowCount has unexpected type %T", x)
	}
	return nil
}

func _ResultSetStats_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*ResultSetStats)
	switch tag {
	case 3: // row_count.row_count_exact
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.RowCount = &ResultSetStats_RowCountExact{int64(x)}
		return true, err
	case 4: // row_count.row_count_lower_bound
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.RowCount = &ResultSetStats_RowCountLowerBound{int64(x)}
		return true, err
	default:
		return false, nil
	}
}

func _ResultSetStats_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*ResultSetStats)
	// row_count
	switch x := m.RowCount.(type) {
	case *ResultSetStats_RowCountExact:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.RowCountExact))
	case *ResultSetStats_RowCountLowerBound:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.RowCountLowerBound))
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

func init() {
	proto.RegisterType((*ResultSet)(nil), "google.spanner.v1.ResultSet")
	proto.RegisterType((*PartialResultSet)(nil), "google.spanner.v1.PartialResultSet")
	proto.RegisterType((*ResultSetMetadata)(nil), "google.spanner.v1.ResultSetMetadata")
	proto.RegisterType((*ResultSetStats)(nil), "google.spanner.v1.ResultSetStats")
}

func init() {
	proto.RegisterFile("google/spanner/v1/result_set.proto", fileDescriptor_result_set_d916e3d6bffb4227)
}

var fileDescriptor_result_set_d916e3d6bffb4227 = []byte{
	// 560 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x93, 0xcf, 0x6e, 0x13, 0x3f,
	0x10, 0xc7, 0x7f, 0x4e, 0xda, 0xfe, 0x12, 0x6f, 0x0a, 0xd4, 0x52, 0x69, 0x14, 0x15, 0x94, 0xa6,
	0x1c, 0x72, 0xda, 0x55, 0xda, 0x03, 0x91, 0x7a, 0xa9, 0x52, 0x21, 0x38, 0x14, 0x29, 0x38, 0x51,
	0x0e, 0x28, 0xd2, 0xca, 0xd9, 0x98, 0x25, 0xea, 0xc6, 0xde, 0xda, 0xde, 0x84, 0x3c, 0x00, 0x67,
	0xee, 0x3c, 0x02, 0x0f, 0xc0, 0x43, 0xf0, 0x3a, 0x5c, 0x38, 0x22, 0xff, 0xd9, 0x24, 0xb0, 0x11,
	0x12, 0x12, 0x37, 0xef, 0xcc, 0xe7, 0xeb, 0x99, 0xef, 0x78, 0x16, 0xb6, 0x62, 0xce, 0xe3, 0x84,
	0x06, 0x32, 0x25, 0x8c, 0x51, 0x11, 0x2c, 0x3a, 0x81, 0xa0, 0x32, 0x4b, 0x54, 0x28, 0xa9, 0xf2,
	0x53, 0xc1, 0x15, 0x47, 0x47, 0x96, 0xf1, 0x1d, 0xe3, 0x2f, 0x3a, 0x8d, 0x53, 0x27, 0x23, 0xe9,
	0x2c, 0x20, 0x8c, 0x71, 0x45, 0xd4, 0x8c, 0x33, 0x69, 0x05, 0xeb, 0xac, 0xf9, 0x9a, 0x64, 0xef,
	0x02, 0xa9, 0x44, 0x16, 0xb9, 0xeb, 0x1a, 0x3b, 0x4a, 0xde, 0x67, 0x54, 0xac, 0xc2, 0x34, 0x21,
	0xcc, 0x31, 0xe7, 0x45, 0x46, 0x09, 0xc2, 0x24, 0x89, 0x74, 0x9d, 0xdf, 0xca, 0x6c, 0x43, 0xab,
	0x94, 0xda, 0x6c, 0xeb, 0x2b, 0x80, 0x55, 0x6c, 0xac, 0x0c, 0xa8, 0x42, 0xd7, 0xb0, 0x32, 0xa7,
	0x8a, 0x4c, 0x89, 0x22, 0x75, 0xd0, 0x04, 0x6d, 0xef, 0xe2, 0x99, 0x5f, 0xb0, 0xe5, 0xaf, 0xf9,
	0xd7, 0x8e, 0xc5, 0x6b, 0x15, 0xf2, 0xe1, 0x9e, 0xe0, 0x4b, 0x59, 0x2f, 0x35, 0xcb, 0x6d, 0xef,
	0xa2, 0x91, 0xab, 0x73, 0x8f, 0xfe, 0xed, 0x4c, 0xaa, 0x11, 0x49, 0x32, 0x8a, 0x0d, 0x87, 0x9e,
	0xc3, 0x7d, 0xa9, 0x88, 0x92, 0xf5, 0xb2, 0x29, 0x77, 0xf6, 0xa7, 0x72, 0x03, 0x0d, 0x62, 0xcb,
	0xb7, 0x3e, 0x96, 0xe0, 0xa3, 0x3e, 0x11, 0x6a, 0x46, 0x92, 0x7f, 0xdb, 0xff, 0xc1, 0x42, 0xb7,
	0x97, 0x3b, 0x78, 0x5c, 0x70, 0x60, 0xbb, 0x77, 0x14, 0x3a, 0x87, 0x87, 0xd1, 0xfb, 0x8c, 0xdd,
	0xd1, 0x69, 0x68, 0x22, 0xc6, 0x47, 0x05, 0xd7, 0x5c, 0xd0, 0xc0, 0xe8, 0x0c, 0xd6, 0xf4, 0xba,
	0xcc, 0x69, 0xa8, 0xf8, 0x1d, 0x65, 0xf5, 0xbd, 0x26, 0x68, 0xd7, 0xb0, 0x67, 0x63, 0x43, 0x1d,
	0xda, 0xcc, 0x61, 0xff, 0x2f, 0xe7, 0xf0, 0x09, 0xc0, 0xa3, 0x82, 0x21, 0xd4, 0x85, 0x15, 0xc1,
	0x97, 0xa1, 0x7e, 0x68, 0x37, 0x88, 0x27, 0x3b, 0x6e, 0x1c, 0x98, 0x85, 0x1b, 0xae, 0x52, 0x8a,
	0xff, 0x17, 0x7c, 0xa9, 0x0f, 0xe8, 0x1a, 0x7a, 0x5b, 0x3b, 0x54, 0x2f, 0x19, 0xf1, 0xd3, 0x1d,
	0xe2, 0xe1, 0x86, 0xc2, 0xdb, 0x92, 0xd6, 0x77, 0x00, 0x1f, 0xfc, 0xda, 0x2b, 0xba, 0x82, 0x70,
	0xb3, 0xbc, 0xae, 0xa1, 0xd3, 0x1d, 0x77, 0xbe, 0xd1, 0x50, 0x3f, 0x21, 0x0c, 0x57, 0xef, 0xf3,
	0x23, 0xea, 0x42, 0xcf, 0x8a, 0xed, 0x80, 0x6c, 0x47, 0x27, 0x85, 0x77, 0xb1, 0x66, 0xb0, 0x2d,
	0x64, 0xcb, 0xb6, 0xe1, 0x43, 0x3d, 0x85, 0x88, 0x67, 0x4c, 0x85, 0xf4, 0x03, 0x89, 0x94, 0x79,
	0x9e, 0xf2, 0xab, 0xff, 0xf0, 0xa1, 0xe0, 0xcb, 0x1b, 0x1d, 0x7f, 0xa1, 0xc3, 0xe8, 0x12, 0x1e,
	0x6f, 0xc8, 0x84, 0x2f, 0xa9, 0x08, 0x27, 0x3c, 0x63, 0x53, 0xf3, 0x54, 0x9a, 0x47, 0x39, 0x7f,
	0xab, 0x93, 0x3d, 0x9d, 0xeb, 0x79, 0xb0, 0xba, 0x16, 0xf5, 0x3e, 0x03, 0x78, 0x1c, 0xf1, 0x79,
	0xd1, 0x54, 0x6f, 0x33, 0x8c, 0xbe, 0xee, 0xb5, 0x0f, 0xde, 0x76, 0x1d, 0x14, 0xf3, 0x84, 0xb0,
	0xd8, 0xe7, 0x22, 0x0e, 0x62, 0xca, 0x8c, 0x93, 0xc0, 0xa6, 0x48, 0x3a, 0x93, 0x5b, 0x7f, 0xec,
	0x95, 0x3b, 0xfe, 0x00, 0xe0, 0x4b, 0xe9, 0xe4, 0xa5, 0x55, 0xdf, 0x24, 0x3c, 0x9b, 0xfa, 0x03,
	0x57, 0x68, 0xd4, 0xf9, 0x96, 0x67, 0xc6, 0x26, 0x33, 0x76, 0x99, 0xf1, 0xa8, 0x33, 0x39, 0x30,
	0x77, 0x5f, 0xfe, 0x0c, 0x00, 0x00, 0xff, 0xff, 0x73, 0xdc, 0x50, 0xf9, 0xc8, 0x04, 0x00, 0x00,
}
