import MUICore_pb2
import MUICore_pb2_grpc
import grpc

def run():
    with grpc.insecure_channel('localhost:50010') as channel:
        s=MUICore_pb2_grpc.ManticoreUIStub(channel)
        print(s)
        r=s.Start(MUICore_pb2.CLIArguments(program_path="/home/kok/Desktop/crackme"))
        print(r)

run()