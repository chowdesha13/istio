# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: mixer/adapter/model/v1beta1/type.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='mixer/adapter/model/v1beta1/type.proto',
  package='istio.mixer.adapter.model.v1beta1',
  syntax='proto3',
  serialized_pb=_b('\n&mixer/adapter/model/v1beta1/type.proto\x12!istio.mixer.adapter.model.v1beta1\"\x07\n\x05Value\"\x0b\n\tIPAddress\"\n\n\x08\x44uration\"\x0b\n\tTimeStamp\"\t\n\x07\x44NSName\"\x0e\n\x0c\x45mailAddress\"\x05\n\x03UriB*Z(istio.io/api/mixer/adapter/model/v1beta1b\x06proto3')
)




_VALUE = _descriptor.Descriptor(
  name='Value',
  full_name='istio.mixer.adapter.model.v1beta1.Value',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=77,
  serialized_end=84,
)


_IPADDRESS = _descriptor.Descriptor(
  name='IPAddress',
  full_name='istio.mixer.adapter.model.v1beta1.IPAddress',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=86,
  serialized_end=97,
)


_DURATION = _descriptor.Descriptor(
  name='Duration',
  full_name='istio.mixer.adapter.model.v1beta1.Duration',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=99,
  serialized_end=109,
)


_TIMESTAMP = _descriptor.Descriptor(
  name='TimeStamp',
  full_name='istio.mixer.adapter.model.v1beta1.TimeStamp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=111,
  serialized_end=122,
)


_DNSNAME = _descriptor.Descriptor(
  name='DNSName',
  full_name='istio.mixer.adapter.model.v1beta1.DNSName',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=124,
  serialized_end=133,
)


_EMAILADDRESS = _descriptor.Descriptor(
  name='EmailAddress',
  full_name='istio.mixer.adapter.model.v1beta1.EmailAddress',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=135,
  serialized_end=149,
)


_URI = _descriptor.Descriptor(
  name='Uri',
  full_name='istio.mixer.adapter.model.v1beta1.Uri',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=151,
  serialized_end=156,
)

DESCRIPTOR.message_types_by_name['Value'] = _VALUE
DESCRIPTOR.message_types_by_name['IPAddress'] = _IPADDRESS
DESCRIPTOR.message_types_by_name['Duration'] = _DURATION
DESCRIPTOR.message_types_by_name['TimeStamp'] = _TIMESTAMP
DESCRIPTOR.message_types_by_name['DNSName'] = _DNSNAME
DESCRIPTOR.message_types_by_name['EmailAddress'] = _EMAILADDRESS
DESCRIPTOR.message_types_by_name['Uri'] = _URI
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Value = _reflection.GeneratedProtocolMessageType('Value', (_message.Message,), dict(
  DESCRIPTOR = _VALUE,
  __module__ = 'mixer.adapter.model.v1beta1.type_pb2'
  # @@protoc_insertion_point(class_scope:istio.mixer.adapter.model.v1beta1.Value)
  ))
_sym_db.RegisterMessage(Value)

IPAddress = _reflection.GeneratedProtocolMessageType('IPAddress', (_message.Message,), dict(
  DESCRIPTOR = _IPADDRESS,
  __module__ = 'mixer.adapter.model.v1beta1.type_pb2'
  # @@protoc_insertion_point(class_scope:istio.mixer.adapter.model.v1beta1.IPAddress)
  ))
_sym_db.RegisterMessage(IPAddress)

Duration = _reflection.GeneratedProtocolMessageType('Duration', (_message.Message,), dict(
  DESCRIPTOR = _DURATION,
  __module__ = 'mixer.adapter.model.v1beta1.type_pb2'
  # @@protoc_insertion_point(class_scope:istio.mixer.adapter.model.v1beta1.Duration)
  ))
_sym_db.RegisterMessage(Duration)

TimeStamp = _reflection.GeneratedProtocolMessageType('TimeStamp', (_message.Message,), dict(
  DESCRIPTOR = _TIMESTAMP,
  __module__ = 'mixer.adapter.model.v1beta1.type_pb2'
  # @@protoc_insertion_point(class_scope:istio.mixer.adapter.model.v1beta1.TimeStamp)
  ))
_sym_db.RegisterMessage(TimeStamp)

DNSName = _reflection.GeneratedProtocolMessageType('DNSName', (_message.Message,), dict(
  DESCRIPTOR = _DNSNAME,
  __module__ = 'mixer.adapter.model.v1beta1.type_pb2'
  # @@protoc_insertion_point(class_scope:istio.mixer.adapter.model.v1beta1.DNSName)
  ))
_sym_db.RegisterMessage(DNSName)

EmailAddress = _reflection.GeneratedProtocolMessageType('EmailAddress', (_message.Message,), dict(
  DESCRIPTOR = _EMAILADDRESS,
  __module__ = 'mixer.adapter.model.v1beta1.type_pb2'
  # @@protoc_insertion_point(class_scope:istio.mixer.adapter.model.v1beta1.EmailAddress)
  ))
_sym_db.RegisterMessage(EmailAddress)

Uri = _reflection.GeneratedProtocolMessageType('Uri', (_message.Message,), dict(
  DESCRIPTOR = _URI,
  __module__ = 'mixer.adapter.model.v1beta1.type_pb2'
  # @@protoc_insertion_point(class_scope:istio.mixer.adapter.model.v1beta1.Uri)
  ))
_sym_db.RegisterMessage(Uri)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('Z(istio.io/api/mixer/adapter/model/v1beta1'))
# @@protoc_insertion_point(module_scope)
