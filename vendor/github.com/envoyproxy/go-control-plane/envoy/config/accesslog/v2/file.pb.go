// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/config/accesslog/v2/file.proto

package v2

import (
	fmt "fmt"
	io "io"
	math "math"

	proto "github.com/gogo/protobuf/proto"
	types "github.com/gogo/protobuf/types"
	_ "github.com/lyft/protoc-gen-validate/validate"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// Custom configuration for an :ref:`AccessLog <envoy_api_msg_config.filter.accesslog.v2.AccessLog>`
// that writes log entries directly to a file. Configures the built-in *envoy.file_access_log*
// AccessLog.
type FileAccessLog struct {
	// A path to a local file to which to write the access log entries.
	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	// Access log format. Envoy supports :ref:`custom access log formats
	// <config_access_log_format>` as well as a :ref:`default format
	// <config_access_log_default_format>`.
	//
	// Types that are valid to be assigned to AccessLogFormat:
	//	*FileAccessLog_Format
	//	*FileAccessLog_JsonFormat
	AccessLogFormat      isFileAccessLog_AccessLogFormat `protobuf_oneof:"access_log_format"`
	XXX_NoUnkeyedLiteral struct{}                        `json:"-"`
	XXX_unrecognized     []byte                          `json:"-"`
	XXX_sizecache        int32                           `json:"-"`
}

func (m *FileAccessLog) Reset()         { *m = FileAccessLog{} }
func (m *FileAccessLog) String() string { return proto.CompactTextString(m) }
func (*FileAccessLog) ProtoMessage()    {}
func (*FileAccessLog) Descriptor() ([]byte, []int) {
	return fileDescriptor_bb42a04cfa71ce3c, []int{0}
}
func (m *FileAccessLog) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *FileAccessLog) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_FileAccessLog.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *FileAccessLog) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FileAccessLog.Merge(m, src)
}
func (m *FileAccessLog) XXX_Size() int {
	return m.Size()
}
func (m *FileAccessLog) XXX_DiscardUnknown() {
	xxx_messageInfo_FileAccessLog.DiscardUnknown(m)
}

var xxx_messageInfo_FileAccessLog proto.InternalMessageInfo

type isFileAccessLog_AccessLogFormat interface {
	isFileAccessLog_AccessLogFormat()
	MarshalTo([]byte) (int, error)
	Size() int
}

type FileAccessLog_Format struct {
	Format string `protobuf:"bytes,2,opt,name=format,proto3,oneof"`
}
type FileAccessLog_JsonFormat struct {
	JsonFormat *types.Struct `protobuf:"bytes,3,opt,name=json_format,json=jsonFormat,proto3,oneof"`
}

func (*FileAccessLog_Format) isFileAccessLog_AccessLogFormat()     {}
func (*FileAccessLog_JsonFormat) isFileAccessLog_AccessLogFormat() {}

func (m *FileAccessLog) GetAccessLogFormat() isFileAccessLog_AccessLogFormat {
	if m != nil {
		return m.AccessLogFormat
	}
	return nil
}

func (m *FileAccessLog) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

func (m *FileAccessLog) GetFormat() string {
	if x, ok := m.GetAccessLogFormat().(*FileAccessLog_Format); ok {
		return x.Format
	}
	return ""
}

func (m *FileAccessLog) GetJsonFormat() *types.Struct {
	if x, ok := m.GetAccessLogFormat().(*FileAccessLog_JsonFormat); ok {
		return x.JsonFormat
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*FileAccessLog) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _FileAccessLog_OneofMarshaler, _FileAccessLog_OneofUnmarshaler, _FileAccessLog_OneofSizer, []interface{}{
		(*FileAccessLog_Format)(nil),
		(*FileAccessLog_JsonFormat)(nil),
	}
}

func _FileAccessLog_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*FileAccessLog)
	// access_log_format
	switch x := m.AccessLogFormat.(type) {
	case *FileAccessLog_Format:
		_ = b.EncodeVarint(2<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.Format)
	case *FileAccessLog_JsonFormat:
		_ = b.EncodeVarint(3<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.JsonFormat); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("FileAccessLog.AccessLogFormat has unexpected type %T", x)
	}
	return nil
}

func _FileAccessLog_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*FileAccessLog)
	switch tag {
	case 2: // access_log_format.format
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.AccessLogFormat = &FileAccessLog_Format{x}
		return true, err
	case 3: // access_log_format.json_format
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(types.Struct)
		err := b.DecodeMessage(msg)
		m.AccessLogFormat = &FileAccessLog_JsonFormat{msg}
		return true, err
	default:
		return false, nil
	}
}

func _FileAccessLog_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*FileAccessLog)
	// access_log_format
	switch x := m.AccessLogFormat.(type) {
	case *FileAccessLog_Format:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.Format)))
		n += len(x.Format)
	case *FileAccessLog_JsonFormat:
		s := proto.Size(x.JsonFormat)
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

func init() {
	proto.RegisterType((*FileAccessLog)(nil), "envoy.config.accesslog.v2.FileAccessLog")
}

func init() {
	proto.RegisterFile("envoy/config/accesslog/v2/file.proto", fileDescriptor_bb42a04cfa71ce3c)
}

var fileDescriptor_bb42a04cfa71ce3c = []byte{
	// 273 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x52, 0x49, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0x4f, 0x4c, 0x4e, 0x4e, 0x2d, 0x2e, 0xce,
	0xc9, 0x4f, 0xd7, 0x2f, 0x33, 0xd2, 0x4f, 0xcb, 0xcc, 0x49, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9,
	0x17, 0x92, 0x04, 0xab, 0xd2, 0x83, 0xa8, 0xd2, 0x83, 0xab, 0xd2, 0x2b, 0x33, 0x92, 0x12, 0x2f,
	0x4b, 0xcc, 0xc9, 0x4c, 0x49, 0x2c, 0x49, 0xd5, 0x87, 0x31, 0x20, 0x7a, 0xa4, 0x64, 0xd2, 0xf3,
	0xf3, 0xd3, 0x73, 0x52, 0xf5, 0xc1, 0xbc, 0xa4, 0xd2, 0x34, 0xfd, 0xe2, 0x92, 0xa2, 0xd2, 0xe4,
	0x12, 0x88, 0xac, 0xd2, 0x4c, 0x46, 0x2e, 0x5e, 0xb7, 0xcc, 0x9c, 0x54, 0x47, 0xb0, 0x59, 0x3e,
	0xf9, 0xe9, 0x42, 0xb2, 0x5c, 0x2c, 0x05, 0x89, 0x25, 0x19, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x9c,
	0x4e, 0x9c, 0xbb, 0x5e, 0x1e, 0x60, 0x66, 0x29, 0x62, 0x52, 0x60, 0x0c, 0x02, 0x0b, 0x0b, 0x49,
	0x70, 0xb1, 0xa5, 0xe5, 0x17, 0xe5, 0x26, 0x96, 0x48, 0x30, 0x81, 0x14, 0x78, 0x30, 0x04, 0x41,
	0xf9, 0x42, 0x56, 0x5c, 0xdc, 0x59, 0xc5, 0xf9, 0x79, 0xf1, 0x50, 0x69, 0x66, 0x05, 0x46, 0x0d,
	0x6e, 0x23, 0x71, 0x3d, 0x88, 0xf5, 0x7a, 0x30, 0xeb, 0xf5, 0x82, 0xc1, 0xd6, 0x7b, 0x30, 0x04,
	0x71, 0x81, 0x54, 0xbb, 0x81, 0x15, 0x3b, 0x09, 0x73, 0x09, 0x42, 0x7c, 0x13, 0x9f, 0x93, 0x9f,
	0x0e, 0x35, 0xc1, 0xc9, 0xed, 0xc4, 0x23, 0x39, 0xc6, 0x0b, 0x8f, 0xe4, 0x18, 0x1f, 0x3c, 0x92,
	0x63, 0xe4, 0x52, 0xcf, 0xcc, 0xd7, 0x03, 0x7b, 0xbf, 0xa0, 0x28, 0xbf, 0xa2, 0x52, 0x0f, 0x67,
	0x48, 0x38, 0x71, 0x82, 0xfc, 0x13, 0x00, 0xb2, 0x2e, 0x80, 0x31, 0x8a, 0xa9, 0xcc, 0x28, 0x89,
	0x0d, 0x6c, 0xb7, 0x31, 0x20, 0x00, 0x00, 0xff, 0xff, 0xe7, 0x5e, 0xb2, 0x21, 0x64, 0x01, 0x00,
	0x00,
}

func (m *FileAccessLog) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *FileAccessLog) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Path) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintFile(dAtA, i, uint64(len(m.Path)))
		i += copy(dAtA[i:], m.Path)
	}
	if m.AccessLogFormat != nil {
		nn1, err := m.AccessLogFormat.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += nn1
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *FileAccessLog_Format) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	dAtA[i] = 0x12
	i++
	i = encodeVarintFile(dAtA, i, uint64(len(m.Format)))
	i += copy(dAtA[i:], m.Format)
	return i, nil
}
func (m *FileAccessLog_JsonFormat) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	if m.JsonFormat != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintFile(dAtA, i, uint64(m.JsonFormat.Size()))
		n2, err := m.JsonFormat.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	return i, nil
}
func encodeVarintFile(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *FileAccessLog) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Path)
	if l > 0 {
		n += 1 + l + sovFile(uint64(l))
	}
	if m.AccessLogFormat != nil {
		n += m.AccessLogFormat.Size()
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *FileAccessLog_Format) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Format)
	n += 1 + l + sovFile(uint64(l))
	return n
}
func (m *FileAccessLog_JsonFormat) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.JsonFormat != nil {
		l = m.JsonFormat.Size()
		n += 1 + l + sovFile(uint64(l))
	}
	return n
}

func sovFile(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozFile(x uint64) (n int) {
	return sovFile(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *FileAccessLog) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowFile
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: FileAccessLog: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: FileAccessLog: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Path", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowFile
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthFile
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthFile
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Path = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Format", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowFile
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthFile
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthFile
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AccessLogFormat = &FileAccessLog_Format{string(dAtA[iNdEx:postIndex])}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field JsonFormat", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowFile
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthFile
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthFile
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			v := &types.Struct{}
			if err := v.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			m.AccessLogFormat = &FileAccessLog_JsonFormat{v}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipFile(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthFile
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthFile
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipFile(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowFile
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowFile
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowFile
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthFile
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthFile
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowFile
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipFile(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthFile
				}
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthFile = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowFile   = fmt.Errorf("proto: integer overflow")
)
