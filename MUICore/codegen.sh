python -m grpc_tools.protoc -I. --python_out=muicore --grpc_python_out=muicore MUICore.proto
sed -i '5s/./from . &/' muicore/MUICore_pb2_grpc.py
