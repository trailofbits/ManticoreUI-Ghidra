import grpc
import MUICore_pb2_grpc
import MUICore_pb2
import time

addrs = [0x401f70,0x401f9b]
def run():
    with grpc.insecure_channel('localhost:50010') as channel:
        stub = MUICore_pb2_grpc.ManticoreUIStub(channel)
#        av1 = stub.TargetAddress(MUICore_pb2.AddressRequest(address=addrs[0],type=MUICore_pb2.AddressRequest.TargetType.AVOID))
#        av2 = stub.TargetAddress(MUICore_pb2.AddressRequest(address=addrs[0],type=MUICore_pb2.AddressRequest.TargetType.AVOID))

        sargs = MUICore_pb2.CLIArguments(program_path="/home/kok/Desktop/crackme")
 #       r = stub.Start(sargs)
        r=MUICore_pb2.ManticoreInstance(uuid="c389992bc30c4e7899e6e80eaefc558f")
        print(r)
        time.sleep(6)
        ml = stub.GetMessageList(r)
        sl = stub.GetStateList(r)
        print(ml.messages)
        print(list(map(lambda x:x.state_id,sl.forked_states)))
      #  r2 = stub.Terminate(r)
       # print(r2)
        

if __name__ == "__main__":
    run()
