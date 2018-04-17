# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: mixer/v1/service.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from mixer.v1 import check_pb2 as mixer_dot_v1_dot_check__pb2
from mixer.v1 import report_pb2 as mixer_dot_v1_dot_report__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='mixer/v1/service.proto',
  package='istio.mixer.v1',
  syntax='proto3',
  serialized_pb=_b('\n\x16mixer/v1/service.proto\x12\x0eistio.mixer.v1\x1a\x14mixer/v1/check.proto\x1a\x15mixer/v1/report.proto2\x9a\x01\n\x05Mixer\x12\x46\n\x05\x43heck\x12\x1c.istio.mixer.v1.CheckRequest\x1a\x1d.istio.mixer.v1.CheckResponse\"\x00\x12I\n\x06Report\x12\x1d.istio.mixer.v1.ReportRequest\x1a\x1e.istio.mixer.v1.ReportResponse\"\x00\x42\x1aZ\x15istio.io/api/mixer/v1\x80\x01\x01\x62\x06proto3')
  ,
  dependencies=[mixer_dot_v1_dot_check__pb2.DESCRIPTOR,mixer_dot_v1_dot_report__pb2.DESCRIPTOR,])



_sym_db.RegisterFileDescriptor(DESCRIPTOR)


DESCRIPTOR.has_options = True
DESCRIPTOR._options = _descriptor._ParseOptions(descriptor_pb2.FileOptions(), _b('Z\025istio.io/api/mixer/v1\200\001\001'))

_MIXER = _descriptor.ServiceDescriptor(
  name='Mixer',
  full_name='istio.mixer.v1.Mixer',
  file=DESCRIPTOR,
  index=0,
  options=None,
  serialized_start=88,
  serialized_end=242,
  methods=[
  _descriptor.MethodDescriptor(
    name='Check',
    full_name='istio.mixer.v1.Mixer.Check',
    index=0,
    containing_service=None,
    input_type=mixer_dot_v1_dot_check__pb2._CHECKREQUEST,
    output_type=mixer_dot_v1_dot_check__pb2._CHECKRESPONSE,
    options=None,
  ),
  _descriptor.MethodDescriptor(
    name='Report',
    full_name='istio.mixer.v1.Mixer.Report',
    index=1,
    containing_service=None,
    input_type=mixer_dot_v1_dot_report__pb2._REPORTREQUEST,
    output_type=mixer_dot_v1_dot_report__pb2._REPORTRESPONSE,
    options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_MIXER)

DESCRIPTOR.services_by_name['Mixer'] = _MIXER

# @@protoc_insertion_point(module_scope)
