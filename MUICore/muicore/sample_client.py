import grpc
import MUICore_pb2_grpc
import MUICore_pb2
import time


def run():
    with grpc.insecure_channel('localhost:50010') as channel:
        stub = MUICore_pb2_grpc.ManticoreUIStub(channel)
        sargs = MUICore_pb2.CLIArguments(program_path="/home/kok/Desktop/crackme")
        r = stub.Start(sargs)
        print(r)
        time.sleep(6)
        ml = stub.GetMessageList(r)
        sl = stub.GetStateList(r)
        print(len(ml.messages))
        print(list(map(lambda x:x.state_id,sl.forked_states)))
        
        r2 = stub.Terminate(r)
        print(r2)
        

if __name__ == "__main__":
    run()
