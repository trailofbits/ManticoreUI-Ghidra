# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: MUI.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='MUI.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\tMUI.proto\"!\n\x11ManticoreInstance\x12\x0c\n\x04uuid\x18\x02 \x01(\t\"$\n\x11TerminateResponse\x12\x0f\n\x07success\x18\x03 \x01(\x08\"\x8e\x02\n\x0c\x43LIArguments\x12\x14\n\x0cprogram_path\x18\x04 \x01(\t\x12\x13\n\x0b\x62inary_args\x18\x05 \x03(\t\x12\x0c\n\x04\x65nvp\x18\x06 \x01(\t\x12\x16\n\x0esymbolic_files\x18\x07 \x03(\t\x12\x16\n\x0e\x63oncrete_start\x18\x08 \x01(\t\x12\x12\n\nstdin_size\x18\t \x01(\t\x12\x45\n\x15\x61\x64\x64itional_mcore_args\x18\n \x03(\x0b\x32&.CLIArguments.AdditionalMcoreArgsEntry\x1a:\n\x18\x41\x64\x64itionalMcoreArgsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\"\xa5\x01\n\x0e\x41\x64\x64ressRequest\x12*\n\x0emcore_instance\x18\x0b \x01(\x0b\x32\x12.ManticoreInstance\x12\x0f\n\x07\x61\x64\x64ress\x18\x0c \x01(\x04\x12(\n\x04type\x18\r \x01(\x0e\x32\x1a.AddressRequest.TargetType\",\n\nTargetType\x12\x08\n\x04\x46IND\x10\x00\x12\t\n\x05\x41VOID\x10\x01\x12\t\n\x05\x43LEAR\x10\x02\"!\n\x0eTargetResponse\x12\x0f\n\x07success\x18\x0e \x01(\x08\x32\xa7\x01\n\x0bManticoreUI\x12\x35\n\tTerminate\x12\x12.ManticoreInstance\x1a\x12.TerminateResponse\"\x00\x12,\n\x05Start\x12\r.CLIArguments\x1a\x12.ManticoreInstance\"\x00\x12\x33\n\rTargetAddress\x12\x0f.AddressRequest\x1a\x0f.TargetResponse\"\x00\x62\x06proto3'
)



_ADDRESSREQUEST_TARGETTYPE = _descriptor.EnumDescriptor(
  name='TargetType',
  full_name='AddressRequest.TargetType',
  filename=None,
  file=DESCRIPTOR,
  create_key=_descriptor._internal_create_key,
  values=[
    _descriptor.EnumValueDescriptor(
      name='FIND', index=0, number=0,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='AVOID', index=1, number=1,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
    _descriptor.EnumValueDescriptor(
      name='CLEAR', index=2, number=2,
      serialized_options=None,
      type=None,
      create_key=_descriptor._internal_create_key),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=481,
  serialized_end=525,
)
_sym_db.RegisterEnumDescriptor(_ADDRESSREQUEST_TARGETTYPE)


_MANTICOREINSTANCE = _descriptor.Descriptor(
  name='ManticoreInstance',
  full_name='ManticoreInstance',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='uuid', full_name='ManticoreInstance.uuid', index=0,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=13,
  serialized_end=46,
)


_TERMINATERESPONSE = _descriptor.Descriptor(
  name='TerminateResponse',
  full_name='TerminateResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='success', full_name='TerminateResponse.success', index=0,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=48,
  serialized_end=84,
)


_CLIARGUMENTS_ADDITIONALMCOREARGSENTRY = _descriptor.Descriptor(
  name='AdditionalMcoreArgsEntry',
  full_name='CLIArguments.AdditionalMcoreArgsEntry',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='CLIArguments.AdditionalMcoreArgsEntry.key', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='CLIArguments.AdditionalMcoreArgsEntry.value', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=b'8\001',
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=299,
  serialized_end=357,
)

_CLIARGUMENTS = _descriptor.Descriptor(
  name='CLIArguments',
  full_name='CLIArguments',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='program_path', full_name='CLIArguments.program_path', index=0,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='binary_args', full_name='CLIArguments.binary_args', index=1,
      number=5, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='envp', full_name='CLIArguments.envp', index=2,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='symbolic_files', full_name='CLIArguments.symbolic_files', index=3,
      number=7, type=9, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='concrete_start', full_name='CLIArguments.concrete_start', index=4,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='stdin_size', full_name='CLIArguments.stdin_size', index=5,
      number=9, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='additional_mcore_args', full_name='CLIArguments.additional_mcore_args', index=6,
      number=10, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_CLIARGUMENTS_ADDITIONALMCOREARGSENTRY, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=87,
  serialized_end=357,
)


_ADDRESSREQUEST = _descriptor.Descriptor(
  name='AddressRequest',
  full_name='AddressRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='mcore_instance', full_name='AddressRequest.mcore_instance', index=0,
      number=11, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='address', full_name='AddressRequest.address', index=1,
      number=12, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='type', full_name='AddressRequest.type', index=2,
      number=13, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _ADDRESSREQUEST_TARGETTYPE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=360,
  serialized_end=525,
)


_TARGETRESPONSE = _descriptor.Descriptor(
  name='TargetResponse',
  full_name='TargetResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='success', full_name='TargetResponse.success', index=0,
      number=14, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=527,
  serialized_end=560,
)

_CLIARGUMENTS_ADDITIONALMCOREARGSENTRY.containing_type = _CLIARGUMENTS
_CLIARGUMENTS.fields_by_name['additional_mcore_args'].message_type = _CLIARGUMENTS_ADDITIONALMCOREARGSENTRY
_ADDRESSREQUEST.fields_by_name['mcore_instance'].message_type = _MANTICOREINSTANCE
_ADDRESSREQUEST.fields_by_name['type'].enum_type = _ADDRESSREQUEST_TARGETTYPE
_ADDRESSREQUEST_TARGETTYPE.containing_type = _ADDRESSREQUEST
DESCRIPTOR.message_types_by_name['ManticoreInstance'] = _MANTICOREINSTANCE
DESCRIPTOR.message_types_by_name['TerminateResponse'] = _TERMINATERESPONSE
DESCRIPTOR.message_types_by_name['CLIArguments'] = _CLIARGUMENTS
DESCRIPTOR.message_types_by_name['AddressRequest'] = _ADDRESSREQUEST
DESCRIPTOR.message_types_by_name['TargetResponse'] = _TARGETRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ManticoreInstance = _reflection.GeneratedProtocolMessageType('ManticoreInstance', (_message.Message,), {
  'DESCRIPTOR' : _MANTICOREINSTANCE,
  '__module__' : 'MUI_pb2'
  # @@protoc_insertion_point(class_scope:ManticoreInstance)
  })
_sym_db.RegisterMessage(ManticoreInstance)

TerminateResponse = _reflection.GeneratedProtocolMessageType('TerminateResponse', (_message.Message,), {
  'DESCRIPTOR' : _TERMINATERESPONSE,
  '__module__' : 'MUI_pb2'
  # @@protoc_insertion_point(class_scope:TerminateResponse)
  })
_sym_db.RegisterMessage(TerminateResponse)

CLIArguments = _reflection.GeneratedProtocolMessageType('CLIArguments', (_message.Message,), {

  'AdditionalMcoreArgsEntry' : _reflection.GeneratedProtocolMessageType('AdditionalMcoreArgsEntry', (_message.Message,), {
    'DESCRIPTOR' : _CLIARGUMENTS_ADDITIONALMCOREARGSENTRY,
    '__module__' : 'MUI_pb2'
    # @@protoc_insertion_point(class_scope:CLIArguments.AdditionalMcoreArgsEntry)
    })
  ,
  'DESCRIPTOR' : _CLIARGUMENTS,
  '__module__' : 'MUI_pb2'
  # @@protoc_insertion_point(class_scope:CLIArguments)
  })
_sym_db.RegisterMessage(CLIArguments)
_sym_db.RegisterMessage(CLIArguments.AdditionalMcoreArgsEntry)

AddressRequest = _reflection.GeneratedProtocolMessageType('AddressRequest', (_message.Message,), {
  'DESCRIPTOR' : _ADDRESSREQUEST,
  '__module__' : 'MUI_pb2'
  # @@protoc_insertion_point(class_scope:AddressRequest)
  })
_sym_db.RegisterMessage(AddressRequest)

TargetResponse = _reflection.GeneratedProtocolMessageType('TargetResponse', (_message.Message,), {
  'DESCRIPTOR' : _TARGETRESPONSE,
  '__module__' : 'MUI_pb2'
  # @@protoc_insertion_point(class_scope:TargetResponse)
  })
_sym_db.RegisterMessage(TargetResponse)


_CLIARGUMENTS_ADDITIONALMCOREARGSENTRY._options = None

_MANTICOREUI = _descriptor.ServiceDescriptor(
  name='ManticoreUI',
  full_name='ManticoreUI',
  file=DESCRIPTOR,
  index=0,
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_start=563,
  serialized_end=730,
  methods=[
  _descriptor.MethodDescriptor(
    name='Terminate',
    full_name='ManticoreUI.Terminate',
    index=0,
    containing_service=None,
    input_type=_MANTICOREINSTANCE,
    output_type=_TERMINATERESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='Start',
    full_name='ManticoreUI.Start',
    index=1,
    containing_service=None,
    input_type=_CLIARGUMENTS,
    output_type=_MANTICOREINSTANCE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
  _descriptor.MethodDescriptor(
    name='TargetAddress',
    full_name='ManticoreUI.TargetAddress',
    index=2,
    containing_service=None,
    input_type=_ADDRESSREQUEST,
    output_type=_TARGETRESPONSE,
    serialized_options=None,
    create_key=_descriptor._internal_create_key,
  ),
])
_sym_db.RegisterServiceDescriptor(_MANTICOREUI)

DESCRIPTOR.services_by_name['ManticoreUI'] = _MANTICOREUI

# @@protoc_insertion_point(module_scope)
