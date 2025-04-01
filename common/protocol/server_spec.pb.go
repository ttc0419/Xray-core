// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        v5.29.4
// source: common/protocol/server_spec.proto

package protocol

import (
	net "github.com/xtls/xray-core/common/net"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ServerEndpoint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address *net.IPOrDomain `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Port    uint32          `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	User    []*User         `protobuf:"bytes,3,rep,name=user,proto3" json:"user,omitempty"`
}

func (x *ServerEndpoint) Reset() {
	*x = ServerEndpoint{}
	mi := &file_common_protocol_server_spec_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ServerEndpoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ServerEndpoint) ProtoMessage() {}

func (x *ServerEndpoint) ProtoReflect() protoreflect.Message {
	mi := &file_common_protocol_server_spec_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ServerEndpoint.ProtoReflect.Descriptor instead.
func (*ServerEndpoint) Descriptor() ([]byte, []int) {
	return file_common_protocol_server_spec_proto_rawDescGZIP(), []int{0}
}

func (x *ServerEndpoint) GetAddress() *net.IPOrDomain {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *ServerEndpoint) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *ServerEndpoint) GetUser() []*User {
	if x != nil {
		return x.User
	}
	return nil
}

var File_common_protocol_server_spec_proto protoreflect.FileDescriptor

var file_common_protocol_server_spec_proto_rawDesc = []byte{
	0x0a, 0x21, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f,
	0x6c, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x73, 0x70, 0x65, 0x63, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x14, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x1a, 0x18, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2f, 0x6e, 0x65, 0x74, 0x2f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x8b, 0x01, 0x0a, 0x0e, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x45, 0x6e, 0x64, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x12, 0x35, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x6e, 0x65, 0x74, 0x2e, 0x49, 0x50, 0x4f, 0x72, 0x44, 0x6f, 0x6d, 0x61, 0x69, 0x6e,
	0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f, 0x72,
	0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x2e, 0x0a,
	0x04, 0x75, 0x73, 0x65, 0x72, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x78, 0x72,
	0x61, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63,
	0x6f, 0x6c, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x42, 0x5e, 0x0a,
	0x18, 0x63, 0x6f, 0x6d, 0x2e, 0x78, 0x72, 0x61, 0x79, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x50, 0x01, 0x5a, 0x29, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x78, 0x74, 0x6c, 0x73, 0x2f, 0x78, 0x72, 0x61,
	0x79, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0xaa, 0x02, 0x14, 0x58, 0x72, 0x61, 0x79, 0x2e, 0x43, 0x6f,
	0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_protocol_server_spec_proto_rawDescOnce sync.Once
	file_common_protocol_server_spec_proto_rawDescData = file_common_protocol_server_spec_proto_rawDesc
)

func file_common_protocol_server_spec_proto_rawDescGZIP() []byte {
	file_common_protocol_server_spec_proto_rawDescOnce.Do(func() {
		file_common_protocol_server_spec_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_protocol_server_spec_proto_rawDescData)
	})
	return file_common_protocol_server_spec_proto_rawDescData
}

var file_common_protocol_server_spec_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_common_protocol_server_spec_proto_goTypes = []any{
	(*ServerEndpoint)(nil), // 0: xray.common.protocol.ServerEndpoint
	(*net.IPOrDomain)(nil), // 1: xray.common.net.IPOrDomain
	(*User)(nil),           // 2: xray.common.protocol.User
}
var file_common_protocol_server_spec_proto_depIdxs = []int32{
	1, // 0: xray.common.protocol.ServerEndpoint.address:type_name -> xray.common.net.IPOrDomain
	2, // 1: xray.common.protocol.ServerEndpoint.user:type_name -> xray.common.protocol.User
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_common_protocol_server_spec_proto_init() }
func file_common_protocol_server_spec_proto_init() {
	if File_common_protocol_server_spec_proto != nil {
		return
	}
	file_common_protocol_user_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_common_protocol_server_spec_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_protocol_server_spec_proto_goTypes,
		DependencyIndexes: file_common_protocol_server_spec_proto_depIdxs,
		MessageInfos:      file_common_protocol_server_spec_proto_msgTypes,
	}.Build()
	File_common_protocol_server_spec_proto = out.File
	file_common_protocol_server_spec_proto_rawDesc = nil
	file_common_protocol_server_spec_proto_goTypes = nil
	file_common_protocol_server_spec_proto_depIdxs = nil
}
