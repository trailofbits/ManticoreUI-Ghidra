from concurrent import futures
import grpc
from grpc._server import _Context
from MUI_pb2 import ManticoreInstance, TerminateResponse, CLIArguments, AddressRequest, TargetResponse, UUID
import MUI_pb2_grpc

from manticore.core.state import StateBase
from manticore.native import Manticore

import uuid

class MUIServicer(MUI_pb2_grpc.ManticoreUIServicer):
    """Provides functionality for the methods set out in the protobuf spec"""

    def __init__(self):
        """Initialises the dict that keeps track of all created manticore instances"""
        self.manticore_instances={}
        self.avoid=set()
        self.find=set()
        
    def Start(self, cli_arguments: CLIArguments, context: _Context) -> ManticoreInstance:
        id = UUID(hexstr=uuid.uuid4().hex)
        try:
            m = Manticore.linux(
                cli_arguments.program_path,
                argv = cli_arguments.binary_args,
                envp = cli_arguments.envp,
                symbolic_files = cli_arguments.symbolic_files,
                concrete_start = cli_arguments.concrete_start,
                stdin_size = 0 if len(cli_arguments.stdin_size)==0 else int(cli_arguments.stdin_size),
                **cli_arguments.additional_mcore_args
            )
            
            def avoid_f(state: StateBase):
                state.abandon()
            
            for addr in self.avoid:
                m.hook(addr)(avoid_f)
                
            def find_f(state: StateBase):
                bufs = state.solve_one_n_batched(state.input_symbols)
                for symbol, buf in zip(state.input_symbols, bufs):
                    print(f"{symbol.name}: {buf!r}\n")
                with m.locked_context() as context:
                    m.kill()
                state.abandon()
            
            for addr in self.find:
                m.hook(addr)(find_f)
                
            m.run()
            self.manticore_instances[id]=m
        except:
            return ManticoreInstance()       
        
        return ManticoreInstance(id=id)
    
    def Terminate(self, mcore_instance: ManticoreInstance, context: _Context) -> TerminateResponse:
        if mcore_instance.id.hexstr not in self.manticore_instances:
            return TerminateResponse(status=TerminateResponse.TerminateStatus.INSTANCE_NOT_FOUND)
        return TerminateResponse(status=TerminateResponse.TerminateStatus.SUCCESS)
    
    def TargetAddress(self, address_request: AddressRequest, context: _Context) -> TargetResponse:
        return TargetResponse(status=TargetResponse.TargetStatus.SUCCESS)

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    MUI_pb2_grpc.add_ManticoreUIServicer_to_server(
        MUIServicer(), server)
    server.add_insecure_port("[::]:3216")
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()