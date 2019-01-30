// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mesh/v1alpha1/network.proto

package v1alpha1

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Network provides information about the endpoints in a routable L3
// network. A single routable L3 network can have one or more service
// registries. Note that the network has no relation to the locality of the
// endpoint. The endpoint locality will be obtained from the service
// registry.
type Network struct {
	// REQUIRED: The list of endpoints in the network (obtained through the
	// constituent service registries or from CIDR ranges). All endpoints in
	// the network are directly accessible to one another.
	Endpoints []*Network_NetworkEndpoints `protobuf:"bytes,2,rep,name=endpoints" json:"endpoints,omitempty"`
	// REQUIRED: Set of gateways associated with the network.
	Gateways []*Network_IstioNetworkGateway `protobuf:"bytes,3,rep,name=gateways" json:"gateways,omitempty"`
}

func (m *Network) Reset()                    { *m = Network{} }
func (m *Network) String() string            { return proto.CompactTextString(m) }
func (*Network) ProtoMessage()               {}
func (*Network) Descriptor() ([]byte, []int) { return fileDescriptorNetwork, []int{0} }

func (m *Network) GetEndpoints() []*Network_NetworkEndpoints {
	if m != nil {
		return m.Endpoints
	}
	return nil
}

func (m *Network) GetGateways() []*Network_IstioNetworkGateway {
	if m != nil {
		return m.Gateways
	}
	return nil
}

// NetworkEndpoints describes how the network associated with an endpoint
// should be inferred. An endpoint will be assigned to a network based on
// the following rules:
//
// 1. Implicitly: If the registry explicitly provides information about
// the network to which the endpoint belongs to. In some cases, its
// possible to indicate the network associated with the endpoint by
// adding ISTIO_META_NETWORK environment variable to the sidecar.
//
// 2. Explicitly:
//
//    a. By matching the registry name with one of the "from_registries"
//    in the mesh config. A "from_registry" can only be assigned to a
//    single network.
//
//    b. By matching the IP against one of the CIDR ranges in a mesh
//    config network. The CIDR ranges must not overlap and be assigned to
//    a single network.
//
// (2) will override (1) if both are present.
type Network_NetworkEndpoints struct {
	// Types that are valid to be assigned to Ne:
	//	*Network_NetworkEndpoints_FromCidr
	//	*Network_NetworkEndpoints_FromRegistry
	Ne isNetwork_NetworkEndpoints_Ne `protobuf_oneof:"ne"`
}

func (m *Network_NetworkEndpoints) Reset()         { *m = Network_NetworkEndpoints{} }
func (m *Network_NetworkEndpoints) String() string { return proto.CompactTextString(m) }
func (*Network_NetworkEndpoints) ProtoMessage()    {}
func (*Network_NetworkEndpoints) Descriptor() ([]byte, []int) {
	return fileDescriptorNetwork, []int{0, 0}
}

type isNetwork_NetworkEndpoints_Ne interface {
	isNetwork_NetworkEndpoints_Ne()
	MarshalTo([]byte) (int, error)
	Size() int
}

type Network_NetworkEndpoints_FromCidr struct {
	FromCidr string `protobuf:"bytes,1,opt,name=from_cidr,json=fromCidr,proto3,oneof"`
}
type Network_NetworkEndpoints_FromRegistry struct {
	FromRegistry string `protobuf:"bytes,2,opt,name=from_registry,json=fromRegistry,proto3,oneof"`
}

func (*Network_NetworkEndpoints_FromCidr) isNetwork_NetworkEndpoints_Ne()     {}
func (*Network_NetworkEndpoints_FromRegistry) isNetwork_NetworkEndpoints_Ne() {}

func (m *Network_NetworkEndpoints) GetNe() isNetwork_NetworkEndpoints_Ne {
	if m != nil {
		return m.Ne
	}
	return nil
}

func (m *Network_NetworkEndpoints) GetFromCidr() string {
	if x, ok := m.GetNe().(*Network_NetworkEndpoints_FromCidr); ok {
		return x.FromCidr
	}
	return ""
}

func (m *Network_NetworkEndpoints) GetFromRegistry() string {
	if x, ok := m.GetNe().(*Network_NetworkEndpoints_FromRegistry); ok {
		return x.FromRegistry
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Network_NetworkEndpoints) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Network_NetworkEndpoints_OneofMarshaler, _Network_NetworkEndpoints_OneofUnmarshaler, _Network_NetworkEndpoints_OneofSizer, []interface{}{
		(*Network_NetworkEndpoints_FromCidr)(nil),
		(*Network_NetworkEndpoints_FromRegistry)(nil),
	}
}

func _Network_NetworkEndpoints_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Network_NetworkEndpoints)
	// ne
	switch x := m.Ne.(type) {
	case *Network_NetworkEndpoints_FromCidr:
		_ = b.EncodeVarint(1<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.FromCidr)
	case *Network_NetworkEndpoints_FromRegistry:
		_ = b.EncodeVarint(2<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.FromRegistry)
	case nil:
	default:
		return fmt.Errorf("Network_NetworkEndpoints.Ne has unexpected type %T", x)
	}
	return nil
}

func _Network_NetworkEndpoints_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Network_NetworkEndpoints)
	switch tag {
	case 1: // ne.from_cidr
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Ne = &Network_NetworkEndpoints_FromCidr{x}
		return true, err
	case 2: // ne.from_registry
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Ne = &Network_NetworkEndpoints_FromRegistry{x}
		return true, err
	default:
		return false, nil
	}
}

func _Network_NetworkEndpoints_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Network_NetworkEndpoints)
	// ne
	switch x := m.Ne.(type) {
	case *Network_NetworkEndpoints_FromCidr:
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.FromCidr)))
		n += len(x.FromCidr)
	case *Network_NetworkEndpoints_FromRegistry:
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.FromRegistry)))
		n += len(x.FromRegistry)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// The gateway associated with this network. Traffic from remote networks
// will arrive at the specified gateway:port. All incoming traffic must
// use mTLS.
type Network_IstioNetworkGateway struct {
	// Types that are valid to be assigned to Gw:
	//	*Network_IstioNetworkGateway_RegistryServiceName
	//	*Network_IstioNetworkGateway_Address
	Gw isNetwork_IstioNetworkGateway_Gw `protobuf_oneof:"gw"`
	// REQUIRED: The port associated with the gateway.
	Port uint32 `protobuf:"varint,3,opt,name=port,proto3" json:"port,omitempty"`
	// The locality associated with an explicitly specified gateway (i.e. ip)
	Locality string `protobuf:"bytes,4,opt,name=locality,proto3" json:"locality,omitempty"`
}

func (m *Network_IstioNetworkGateway) Reset()         { *m = Network_IstioNetworkGateway{} }
func (m *Network_IstioNetworkGateway) String() string { return proto.CompactTextString(m) }
func (*Network_IstioNetworkGateway) ProtoMessage()    {}
func (*Network_IstioNetworkGateway) Descriptor() ([]byte, []int) {
	return fileDescriptorNetwork, []int{0, 1}
}

type isNetwork_IstioNetworkGateway_Gw interface {
	isNetwork_IstioNetworkGateway_Gw()
	MarshalTo([]byte) (int, error)
	Size() int
}

type Network_IstioNetworkGateway_RegistryServiceName struct {
	RegistryServiceName string `protobuf:"bytes,1,opt,name=registry_service_name,json=registryServiceName,proto3,oneof"`
}
type Network_IstioNetworkGateway_Address struct {
	Address string `protobuf:"bytes,2,opt,name=address,proto3,oneof"`
}

func (*Network_IstioNetworkGateway_RegistryServiceName) isNetwork_IstioNetworkGateway_Gw() {}
func (*Network_IstioNetworkGateway_Address) isNetwork_IstioNetworkGateway_Gw()             {}

func (m *Network_IstioNetworkGateway) GetGw() isNetwork_IstioNetworkGateway_Gw {
	if m != nil {
		return m.Gw
	}
	return nil
}

func (m *Network_IstioNetworkGateway) GetRegistryServiceName() string {
	if x, ok := m.GetGw().(*Network_IstioNetworkGateway_RegistryServiceName); ok {
		return x.RegistryServiceName
	}
	return ""
}

func (m *Network_IstioNetworkGateway) GetAddress() string {
	if x, ok := m.GetGw().(*Network_IstioNetworkGateway_Address); ok {
		return x.Address
	}
	return ""
}

func (m *Network_IstioNetworkGateway) GetPort() uint32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *Network_IstioNetworkGateway) GetLocality() string {
	if m != nil {
		return m.Locality
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*Network_IstioNetworkGateway) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _Network_IstioNetworkGateway_OneofMarshaler, _Network_IstioNetworkGateway_OneofUnmarshaler, _Network_IstioNetworkGateway_OneofSizer, []interface{}{
		(*Network_IstioNetworkGateway_RegistryServiceName)(nil),
		(*Network_IstioNetworkGateway_Address)(nil),
	}
}

func _Network_IstioNetworkGateway_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*Network_IstioNetworkGateway)
	// gw
	switch x := m.Gw.(type) {
	case *Network_IstioNetworkGateway_RegistryServiceName:
		_ = b.EncodeVarint(1<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.RegistryServiceName)
	case *Network_IstioNetworkGateway_Address:
		_ = b.EncodeVarint(2<<3 | proto.WireBytes)
		_ = b.EncodeStringBytes(x.Address)
	case nil:
	default:
		return fmt.Errorf("Network_IstioNetworkGateway.Gw has unexpected type %T", x)
	}
	return nil
}

func _Network_IstioNetworkGateway_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*Network_IstioNetworkGateway)
	switch tag {
	case 1: // gw.registry_service_name
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Gw = &Network_IstioNetworkGateway_RegistryServiceName{x}
		return true, err
	case 2: // gw.address
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Gw = &Network_IstioNetworkGateway_Address{x}
		return true, err
	default:
		return false, nil
	}
}

func _Network_IstioNetworkGateway_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*Network_IstioNetworkGateway)
	// gw
	switch x := m.Gw.(type) {
	case *Network_IstioNetworkGateway_RegistryServiceName:
		n += proto.SizeVarint(1<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.RegistryServiceName)))
		n += len(x.RegistryServiceName)
	case *Network_IstioNetworkGateway_Address:
		n += proto.SizeVarint(2<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(len(x.Address)))
		n += len(x.Address)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// MeshNetworks (config map) provides information about the set of networks
// inside a mesh and how to route to endpoints in each network. For example
//
// MeshNetworks(file/config map):
// networks:
// - network1:
//   - endpoints:
//     - fromRegistry: registry1 #must match secret name in kubernetes
//     - fromCidr: 192.168.100.0/22 #a VM network for example
//     gateways:
//     - registryServiceName: istio-ingressgateway.istio-system.svc.cluster.local
//       port: 15443
//       locality: us-east-1a
type MeshNetworks struct {
	// REQUIRED: The set of networks inside this mesh. Each network should
	// have a unique name and information about how to infer the endpoints in
	// the network as well as the gateways associated with the network.
	Networks map[string]*Network `protobuf:"bytes,1,rep,name=networks" json:"networks,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value"`
}

func (m *MeshNetworks) Reset()                    { *m = MeshNetworks{} }
func (m *MeshNetworks) String() string            { return proto.CompactTextString(m) }
func (*MeshNetworks) ProtoMessage()               {}
func (*MeshNetworks) Descriptor() ([]byte, []int) { return fileDescriptorNetwork, []int{1} }

func (m *MeshNetworks) GetNetworks() map[string]*Network {
	if m != nil {
		return m.Networks
	}
	return nil
}

func init() {
	proto.RegisterType((*Network)(nil), "istio.mesh.v1alpha1.Network")
	proto.RegisterType((*Network_NetworkEndpoints)(nil), "istio.mesh.v1alpha1.Network.NetworkEndpoints")
	proto.RegisterType((*Network_IstioNetworkGateway)(nil), "istio.mesh.v1alpha1.Network.IstioNetworkGateway")
	proto.RegisterType((*MeshNetworks)(nil), "istio.mesh.v1alpha1.MeshNetworks")
}
func (m *Network) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Network) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Endpoints) > 0 {
		for _, msg := range m.Endpoints {
			dAtA[i] = 0x12
			i++
			i = encodeVarintNetwork(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.Gateways) > 0 {
		for _, msg := range m.Gateways {
			dAtA[i] = 0x1a
			i++
			i = encodeVarintNetwork(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func (m *Network_NetworkEndpoints) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Network_NetworkEndpoints) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Ne != nil {
		nn1, err := m.Ne.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += nn1
	}
	return i, nil
}

func (m *Network_NetworkEndpoints_FromCidr) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	dAtA[i] = 0xa
	i++
	i = encodeVarintNetwork(dAtA, i, uint64(len(m.FromCidr)))
	i += copy(dAtA[i:], m.FromCidr)
	return i, nil
}
func (m *Network_NetworkEndpoints_FromRegistry) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	dAtA[i] = 0x12
	i++
	i = encodeVarintNetwork(dAtA, i, uint64(len(m.FromRegistry)))
	i += copy(dAtA[i:], m.FromRegistry)
	return i, nil
}
func (m *Network_IstioNetworkGateway) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Network_IstioNetworkGateway) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Gw != nil {
		nn2, err := m.Gw.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += nn2
	}
	if m.Port != 0 {
		dAtA[i] = 0x18
		i++
		i = encodeVarintNetwork(dAtA, i, uint64(m.Port))
	}
	if len(m.Locality) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintNetwork(dAtA, i, uint64(len(m.Locality)))
		i += copy(dAtA[i:], m.Locality)
	}
	return i, nil
}

func (m *Network_IstioNetworkGateway_RegistryServiceName) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	dAtA[i] = 0xa
	i++
	i = encodeVarintNetwork(dAtA, i, uint64(len(m.RegistryServiceName)))
	i += copy(dAtA[i:], m.RegistryServiceName)
	return i, nil
}
func (m *Network_IstioNetworkGateway_Address) MarshalTo(dAtA []byte) (int, error) {
	i := 0
	dAtA[i] = 0x12
	i++
	i = encodeVarintNetwork(dAtA, i, uint64(len(m.Address)))
	i += copy(dAtA[i:], m.Address)
	return i, nil
}
func (m *MeshNetworks) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *MeshNetworks) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Networks) > 0 {
		for k, _ := range m.Networks {
			dAtA[i] = 0xa
			i++
			v := m.Networks[k]
			msgSize := 0
			if v != nil {
				msgSize = v.Size()
				msgSize += 1 + sovNetwork(uint64(msgSize))
			}
			mapSize := 1 + len(k) + sovNetwork(uint64(len(k))) + msgSize
			i = encodeVarintNetwork(dAtA, i, uint64(mapSize))
			dAtA[i] = 0xa
			i++
			i = encodeVarintNetwork(dAtA, i, uint64(len(k)))
			i += copy(dAtA[i:], k)
			if v != nil {
				dAtA[i] = 0x12
				i++
				i = encodeVarintNetwork(dAtA, i, uint64(v.Size()))
				n3, err := v.MarshalTo(dAtA[i:])
				if err != nil {
					return 0, err
				}
				i += n3
			}
		}
	}
	return i, nil
}

func encodeVarintNetwork(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *Network) Size() (n int) {
	var l int
	_ = l
	if len(m.Endpoints) > 0 {
		for _, e := range m.Endpoints {
			l = e.Size()
			n += 1 + l + sovNetwork(uint64(l))
		}
	}
	if len(m.Gateways) > 0 {
		for _, e := range m.Gateways {
			l = e.Size()
			n += 1 + l + sovNetwork(uint64(l))
		}
	}
	return n
}

func (m *Network_NetworkEndpoints) Size() (n int) {
	var l int
	_ = l
	if m.Ne != nil {
		n += m.Ne.Size()
	}
	return n
}

func (m *Network_NetworkEndpoints_FromCidr) Size() (n int) {
	var l int
	_ = l
	l = len(m.FromCidr)
	n += 1 + l + sovNetwork(uint64(l))
	return n
}
func (m *Network_NetworkEndpoints_FromRegistry) Size() (n int) {
	var l int
	_ = l
	l = len(m.FromRegistry)
	n += 1 + l + sovNetwork(uint64(l))
	return n
}
func (m *Network_IstioNetworkGateway) Size() (n int) {
	var l int
	_ = l
	if m.Gw != nil {
		n += m.Gw.Size()
	}
	if m.Port != 0 {
		n += 1 + sovNetwork(uint64(m.Port))
	}
	l = len(m.Locality)
	if l > 0 {
		n += 1 + l + sovNetwork(uint64(l))
	}
	return n
}

func (m *Network_IstioNetworkGateway_RegistryServiceName) Size() (n int) {
	var l int
	_ = l
	l = len(m.RegistryServiceName)
	n += 1 + l + sovNetwork(uint64(l))
	return n
}
func (m *Network_IstioNetworkGateway_Address) Size() (n int) {
	var l int
	_ = l
	l = len(m.Address)
	n += 1 + l + sovNetwork(uint64(l))
	return n
}
func (m *MeshNetworks) Size() (n int) {
	var l int
	_ = l
	if len(m.Networks) > 0 {
		for k, v := range m.Networks {
			_ = k
			_ = v
			l = 0
			if v != nil {
				l = v.Size()
				l += 1 + sovNetwork(uint64(l))
			}
			mapEntrySize := 1 + len(k) + sovNetwork(uint64(len(k))) + l
			n += mapEntrySize + 1 + sovNetwork(uint64(mapEntrySize))
		}
	}
	return n
}

func sovNetwork(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozNetwork(x uint64) (n int) {
	return sovNetwork(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Network) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetwork
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Network: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Network: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Endpoints", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Endpoints = append(m.Endpoints, &Network_NetworkEndpoints{})
			if err := m.Endpoints[len(m.Endpoints)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Gateways", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gateways = append(m.Gateways, &Network_IstioNetworkGateway{})
			if err := m.Gateways[len(m.Gateways)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetwork(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthNetwork
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Network_NetworkEndpoints) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetwork
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: NetworkEndpoints: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: NetworkEndpoints: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FromCidr", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Ne = &Network_NetworkEndpoints_FromCidr{string(dAtA[iNdEx:postIndex])}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field FromRegistry", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Ne = &Network_NetworkEndpoints_FromRegistry{string(dAtA[iNdEx:postIndex])}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetwork(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthNetwork
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Network_IstioNetworkGateway) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetwork
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: IstioNetworkGateway: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: IstioNetworkGateway: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RegistryServiceName", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gw = &Network_IstioNetworkGateway_RegistryServiceName{string(dAtA[iNdEx:postIndex])}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Address", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Gw = &Network_IstioNetworkGateway_Address{string(dAtA[iNdEx:postIndex])}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Port", wireType)
			}
			m.Port = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Port |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Locality", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Locality = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetwork(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthNetwork
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *MeshNetworks) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowNetwork
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MeshNetworks: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MeshNetworks: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Networks", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowNetwork
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthNetwork
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Networks == nil {
				m.Networks = make(map[string]*Network)
			}
			var mapkey string
			var mapvalue *Network
			for iNdEx < postIndex {
				entryPreIndex := iNdEx
				var wire uint64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowNetwork
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					wire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				fieldNum := int32(wire >> 3)
				if fieldNum == 1 {
					var stringLenmapkey uint64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowNetwork
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						stringLenmapkey |= (uint64(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					intStringLenmapkey := int(stringLenmapkey)
					if intStringLenmapkey < 0 {
						return ErrInvalidLengthNetwork
					}
					postStringIndexmapkey := iNdEx + intStringLenmapkey
					if postStringIndexmapkey > l {
						return io.ErrUnexpectedEOF
					}
					mapkey = string(dAtA[iNdEx:postStringIndexmapkey])
					iNdEx = postStringIndexmapkey
				} else if fieldNum == 2 {
					var mapmsglen int
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowNetwork
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						mapmsglen |= (int(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					if mapmsglen < 0 {
						return ErrInvalidLengthNetwork
					}
					postmsgIndex := iNdEx + mapmsglen
					if mapmsglen < 0 {
						return ErrInvalidLengthNetwork
					}
					if postmsgIndex > l {
						return io.ErrUnexpectedEOF
					}
					mapvalue = &Network{}
					if err := mapvalue.Unmarshal(dAtA[iNdEx:postmsgIndex]); err != nil {
						return err
					}
					iNdEx = postmsgIndex
				} else {
					iNdEx = entryPreIndex
					skippy, err := skipNetwork(dAtA[iNdEx:])
					if err != nil {
						return err
					}
					if skippy < 0 {
						return ErrInvalidLengthNetwork
					}
					if (iNdEx + skippy) > postIndex {
						return io.ErrUnexpectedEOF
					}
					iNdEx += skippy
				}
			}
			m.Networks[mapkey] = mapvalue
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipNetwork(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthNetwork
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipNetwork(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowNetwork
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
					return 0, ErrIntOverflowNetwork
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
					return 0, ErrIntOverflowNetwork
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
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthNetwork
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowNetwork
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
				next, err := skipNetwork(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
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
	ErrInvalidLengthNetwork = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowNetwork   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("mesh/v1alpha1/network.proto", fileDescriptorNetwork) }

var fileDescriptorNetwork = []byte{
	// 403 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x92, 0xcf, 0x8e, 0xda, 0x30,
	0x10, 0xc6, 0xeb, 0x84, 0x96, 0x30, 0x80, 0x84, 0x8c, 0x2a, 0x45, 0x69, 0x8b, 0x10, 0x52, 0xa5,
	0x5c, 0x9a, 0x14, 0xda, 0x43, 0xd5, 0x23, 0x15, 0x6a, 0x2b, 0x5a, 0x0e, 0xee, 0xa9, 0x3d, 0x14,
	0xb9, 0xc4, 0x05, 0x8b, 0x24, 0x8e, 0x6c, 0x2f, 0x28, 0x0f, 0xb3, 0xb7, 0x7d, 0x86, 0x7d, 0x86,
	0x3d, 0xee, 0x23, 0xac, 0x78, 0x92, 0x55, 0xfe, 0xee, 0xb2, 0x42, 0x9c, 0x6c, 0xcf, 0xf7, 0xfd,
	0x66, 0xc6, 0x63, 0xc3, 0xab, 0x88, 0xa9, 0x8d, 0xbf, 0x1b, 0xd3, 0x30, 0xd9, 0xd0, 0xb1, 0x1f,
	0x33, 0xbd, 0x17, 0x72, 0xeb, 0x25, 0x52, 0x68, 0x81, 0xfb, 0x5c, 0x69, 0x2e, 0xbc, 0xcc, 0xe2,
	0x55, 0x96, 0xd1, 0x95, 0x09, 0xcd, 0x45, 0x61, 0xc3, 0x73, 0x68, 0xb1, 0x38, 0x48, 0x04, 0x8f,
	0xb5, 0xb2, 0x8d, 0xa1, 0xe9, 0xb6, 0x27, 0xef, 0xbc, 0x13, 0x90, 0x57, 0x02, 0xd5, 0x3a, 0xab,
	0x20, 0xf2, 0xc0, 0xe3, 0x1f, 0x60, 0xad, 0xa9, 0x66, 0x7b, 0x9a, 0x2a, 0xdb, 0xcc, 0x73, 0xbd,
	0x3f, 0x9b, 0xeb, 0x7b, 0xa6, 0x95, 0x87, 0xaf, 0x05, 0x48, 0xea, 0x0c, 0xce, 0x5f, 0xe8, 0x3d,
	0x2d, 0x86, 0xdf, 0x40, 0xeb, 0xbf, 0x14, 0xd1, 0x72, 0xc5, 0x03, 0x69, 0xa3, 0x21, 0x72, 0x5b,
	0xdf, 0x9e, 0x11, 0x2b, 0x0b, 0x7d, 0xe1, 0x81, 0xc4, 0x6f, 0xa1, 0x9b, 0xcb, 0x92, 0xad, 0xb9,
	0xd2, 0x32, 0xb5, 0x8d, 0xd2, 0xd2, 0xc9, 0xc2, 0xa4, 0x8c, 0x4e, 0x1b, 0x60, 0xc4, 0xcc, 0xb9,
	0x44, 0xd0, 0x3f, 0xd1, 0x01, 0xfe, 0x08, 0x2f, 0x2b, 0x7e, 0xa9, 0x98, 0xdc, 0xf1, 0x15, 0x5b,
	0xc6, 0x34, 0x62, 0x75, 0xbd, 0x7e, 0x25, 0xff, 0x2a, 0xd4, 0x05, 0x8d, 0x18, 0x76, 0xa0, 0x49,
	0x83, 0x40, 0x32, 0xa5, 0xea, 0xa2, 0x55, 0x00, 0x63, 0x68, 0x24, 0x42, 0x6a, 0xdb, 0x1c, 0x22,
	0xb7, 0x4b, 0xf2, 0x3d, 0x76, 0xc0, 0x0a, 0xc5, 0x8a, 0x86, 0x5c, 0xa7, 0x76, 0x23, 0x03, 0x48,
	0x7d, 0xce, 0xfa, 0x5b, 0xef, 0x47, 0xd7, 0x08, 0x3a, 0x3f, 0x99, 0xda, 0x94, 0xed, 0x29, 0x3c,
	0x07, 0xab, 0x7c, 0x5d, 0x65, 0xa3, 0x7c, 0xbc, 0xfe, 0xc9, 0xf1, 0x3e, 0x86, 0xaa, 0x59, 0xab,
	0x59, 0xac, 0x65, 0x4a, 0xea, 0x04, 0xce, 0x6f, 0xe8, 0x1e, 0x49, 0xb8, 0x07, 0xe6, 0x96, 0xa5,
	0xc5, 0x25, 0x49, 0xb6, 0xc5, 0x13, 0x78, 0xbe, 0xa3, 0xe1, 0x05, 0xcb, 0x2f, 0xd4, 0x9e, 0xbc,
	0x3e, 0xf7, 0x96, 0xa4, 0xb0, 0x7e, 0x36, 0x3e, 0xa1, 0xa9, 0x7b, 0x73, 0x18, 0xa0, 0xdb, 0xc3,
	0x00, 0xdd, 0x1d, 0x06, 0xe8, 0x8f, 0x53, 0x50, 0x5c, 0xf8, 0x34, 0xe1, 0xfe, 0xd1, 0x67, 0xfd,
	0xf7, 0x22, 0xff, 0xa5, 0x1f, 0xee, 0x03, 0x00, 0x00, 0xff, 0xff, 0xbc, 0x70, 0x44, 0x24, 0xc4,
	0x02, 0x00, 0x00,
}
