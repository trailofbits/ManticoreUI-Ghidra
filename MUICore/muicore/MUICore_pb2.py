# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: muicore/MUICore.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15muicore/MUICore.proto\x12\x07muicore\" \n\rMUILogMessage\x12\x0f\n\x07\x63ontent\x18\x01 \x01(\t\":\n\x0eMUIMessageList\x12(\n\x08messages\x18\x02 \x03(\x0b\x32\x16.muicore.MUILogMessage\"Q\n\x08MUIState\x12\x10\n\x08state_id\x18\x03 \x01(\x05\x12\n\n\x02pc\x18\n \x01(\x04\x12\x11\n\tparent_id\x18\x1c \x01(\x05\x12\x14\n\x0c\x63hildren_ids\x18\x1d \x03(\x05\"\xe4\x01\n\x0cMUIStateList\x12(\n\ractive_states\x18\x04 \x03(\x0b\x32\x11.muicore.MUIState\x12)\n\x0ewaiting_states\x18\x05 \x03(\x0b\x32\x11.muicore.MUIState\x12(\n\rforked_states\x18\x06 \x03(\x0b\x32\x11.muicore.MUIState\x12)\n\x0e\x65rrored_states\x18\x07 \x03(\x0b\x32\x11.muicore.MUIState\x12*\n\x0f\x63omplete_states\x18\x08 \x03(\x0b\x32\x11.muicore.MUIState\"!\n\x11ManticoreInstance\x12\x0c\n\x04uuid\x18\t \x01(\t\"\x13\n\x11TerminateResponse\"\x89\x01\n\x04Hook\x12\x0f\n\x07\x61\x64\x64ress\x18\x1a \x01(\x04\x12$\n\x04type\x18\x1b \x01(\x0e\x32\x16.muicore.Hook.HookType\x12\x11\n\thook_func\x18\x1f \x01(\t\"7\n\x08HookType\x12\x08\n\x04\x46IND\x10\x00\x12\t\n\x05\x41VOID\x10\x01\x12\n\n\x06\x43USTOM\x10\x02\x12\n\n\x06GLOBAL\x10\x03\"\xcb\x01\n\x0fNativeArguments\x12\x14\n\x0cprogram_path\x18\x0b \x01(\t\x12\x13\n\x0b\x62inary_args\x18\x10 \x03(\t\x12\x0c\n\x04\x65nvp\x18\x11 \x03(\t\x12\x16\n\x0esymbolic_files\x18\x12 \x03(\t\x12\x16\n\x0e\x63oncrete_start\x18\x13 \x01(\t\x12\x12\n\nstdin_size\x18\x14 \x01(\t\x12\x1d\n\x15\x61\x64\x64itional_mcore_args\x18\x15 \x01(\t\x12\x1c\n\x05hooks\x18\x1e \x03(\x0b\x32\r.muicore.Hook\"\xac\x01\n\x0c\x45VMArguments\x12\x15\n\rcontract_path\x18\x0c \x01(\t\x12\x15\n\rcontract_name\x18\r \x01(\t\x12\x10\n\x08solc_bin\x18\x0e \x01(\t\x12\x10\n\x08tx_limit\x18\x16 \x01(\t\x12\x12\n\ntx_account\x18\x17 \x01(\t\x12\x1c\n\x14\x64\x65tectors_to_exclude\x18\x18 \x03(\t\x12\x18\n\x10\x61\x64\x64itional_flags\x18\x19 \x01(\t\",\n\x16ManticoreRunningStatus\x12\x12\n\nis_running\x18\x0f \x01(\x08\"\x13\n\x11StopServerRequest\"\x14\n\x12StopServerResponse2\x8b\x04\n\x0bManticoreUI\x12\x45\n\x0bStartNative\x12\x18.muicore.NativeArguments\x1a\x1a.muicore.ManticoreInstance\"\x00\x12?\n\x08StartEVM\x12\x15.muicore.EVMArguments\x1a\x1a.muicore.ManticoreInstance\"\x00\x12\x45\n\tTerminate\x12\x1a.muicore.ManticoreInstance\x1a\x1a.muicore.TerminateResponse\"\x00\x12\x43\n\x0cGetStateList\x12\x1a.muicore.ManticoreInstance\x1a\x15.muicore.MUIStateList\"\x00\x12G\n\x0eGetMessageList\x12\x1a.muicore.ManticoreInstance\x1a\x17.muicore.MUIMessageList\"\x00\x12V\n\x15\x43heckManticoreRunning\x12\x1a.muicore.ManticoreInstance\x1a\x1f.muicore.ManticoreRunningStatus\"\x00\x12G\n\nStopServer\x12\x1a.muicore.StopServerRequest\x1a\x1b.muicore.StopServerResponse\"\x00\x62\x06proto3')



_MUILOGMESSAGE = DESCRIPTOR.message_types_by_name['MUILogMessage']
_MUIMESSAGELIST = DESCRIPTOR.message_types_by_name['MUIMessageList']
_MUISTATE = DESCRIPTOR.message_types_by_name['MUIState']
_MUISTATELIST = DESCRIPTOR.message_types_by_name['MUIStateList']
_MANTICOREINSTANCE = DESCRIPTOR.message_types_by_name['ManticoreInstance']
_TERMINATERESPONSE = DESCRIPTOR.message_types_by_name['TerminateResponse']
_HOOK = DESCRIPTOR.message_types_by_name['Hook']
_NATIVEARGUMENTS = DESCRIPTOR.message_types_by_name['NativeArguments']
_EVMARGUMENTS = DESCRIPTOR.message_types_by_name['EVMArguments']
_MANTICORERUNNINGSTATUS = DESCRIPTOR.message_types_by_name['ManticoreRunningStatus']
_STOPSERVERREQUEST = DESCRIPTOR.message_types_by_name['StopServerRequest']
_STOPSERVERRESPONSE = DESCRIPTOR.message_types_by_name['StopServerResponse']
_HOOK_HOOKTYPE = _HOOK.enum_types_by_name['HookType']
MUILogMessage = _reflection.GeneratedProtocolMessageType('MUILogMessage', (_message.Message,), {
  'DESCRIPTOR' : _MUILOGMESSAGE,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.MUILogMessage)
  })
_sym_db.RegisterMessage(MUILogMessage)

MUIMessageList = _reflection.GeneratedProtocolMessageType('MUIMessageList', (_message.Message,), {
  'DESCRIPTOR' : _MUIMESSAGELIST,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.MUIMessageList)
  })
_sym_db.RegisterMessage(MUIMessageList)

MUIState = _reflection.GeneratedProtocolMessageType('MUIState', (_message.Message,), {
  'DESCRIPTOR' : _MUISTATE,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.MUIState)
  })
_sym_db.RegisterMessage(MUIState)

MUIStateList = _reflection.GeneratedProtocolMessageType('MUIStateList', (_message.Message,), {
  'DESCRIPTOR' : _MUISTATELIST,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.MUIStateList)
  })
_sym_db.RegisterMessage(MUIStateList)

ManticoreInstance = _reflection.GeneratedProtocolMessageType('ManticoreInstance', (_message.Message,), {
  'DESCRIPTOR' : _MANTICOREINSTANCE,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.ManticoreInstance)
  })
_sym_db.RegisterMessage(ManticoreInstance)

TerminateResponse = _reflection.GeneratedProtocolMessageType('TerminateResponse', (_message.Message,), {
  'DESCRIPTOR' : _TERMINATERESPONSE,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.TerminateResponse)
  })
_sym_db.RegisterMessage(TerminateResponse)

Hook = _reflection.GeneratedProtocolMessageType('Hook', (_message.Message,), {
  'DESCRIPTOR' : _HOOK,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.Hook)
  })
_sym_db.RegisterMessage(Hook)

NativeArguments = _reflection.GeneratedProtocolMessageType('NativeArguments', (_message.Message,), {
  'DESCRIPTOR' : _NATIVEARGUMENTS,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.NativeArguments)
  })
_sym_db.RegisterMessage(NativeArguments)

EVMArguments = _reflection.GeneratedProtocolMessageType('EVMArguments', (_message.Message,), {
  'DESCRIPTOR' : _EVMARGUMENTS,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.EVMArguments)
  })
_sym_db.RegisterMessage(EVMArguments)

ManticoreRunningStatus = _reflection.GeneratedProtocolMessageType('ManticoreRunningStatus', (_message.Message,), {
  'DESCRIPTOR' : _MANTICORERUNNINGSTATUS,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.ManticoreRunningStatus)
  })
_sym_db.RegisterMessage(ManticoreRunningStatus)

StopServerRequest = _reflection.GeneratedProtocolMessageType('StopServerRequest', (_message.Message,), {
  'DESCRIPTOR' : _STOPSERVERREQUEST,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.StopServerRequest)
  })
_sym_db.RegisterMessage(StopServerRequest)

StopServerResponse = _reflection.GeneratedProtocolMessageType('StopServerResponse', (_message.Message,), {
  'DESCRIPTOR' : _STOPSERVERRESPONSE,
  '__module__' : 'muicore.MUICore_pb2'
  # @@protoc_insertion_point(class_scope:muicore.StopServerResponse)
  })
_sym_db.RegisterMessage(StopServerResponse)

_MANTICOREUI = DESCRIPTOR.services_by_name['ManticoreUI']
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _MUILOGMESSAGE._serialized_start=34
  _MUILOGMESSAGE._serialized_end=66
  _MUIMESSAGELIST._serialized_start=68
  _MUIMESSAGELIST._serialized_end=126
  _MUISTATE._serialized_start=128
  _MUISTATE._serialized_end=209
  _MUISTATELIST._serialized_start=212
  _MUISTATELIST._serialized_end=440
  _MANTICOREINSTANCE._serialized_start=442
  _MANTICOREINSTANCE._serialized_end=475
  _TERMINATERESPONSE._serialized_start=477
  _TERMINATERESPONSE._serialized_end=496
  _HOOK._serialized_start=499
  _HOOK._serialized_end=636
  _HOOK_HOOKTYPE._serialized_start=581
  _HOOK_HOOKTYPE._serialized_end=636
  _NATIVEARGUMENTS._serialized_start=639
  _NATIVEARGUMENTS._serialized_end=842
  _EVMARGUMENTS._serialized_start=845
  _EVMARGUMENTS._serialized_end=1017
  _MANTICORERUNNINGSTATUS._serialized_start=1019
  _MANTICORERUNNINGSTATUS._serialized_end=1063
  _STOPSERVERREQUEST._serialized_start=1065
  _STOPSERVERREQUEST._serialized_end=1084
  _STOPSERVERRESPONSE._serialized_start=1086
  _STOPSERVERRESPONSE._serialized_end=1106
  _MANTICOREUI._serialized_start=1109
  _MANTICOREUI._serialized_end=1632
# @@protoc_insertion_point(module_scope)
