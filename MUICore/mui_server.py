from concurrent import futures
from threading import Thread

import grpc
from grpc._server import _Context
from MUICore_pb2 import (
    ManticoreInstance,
    TerminateResponse,
    CLIArguments,
    AddressRequest,
    TargetResponse,
)
import MUICore_pb2_grpc

from manticore.core.state import StateBase
from manticore.native import Manticore
from manticore.core.plugin import InstructionCounter, Visited, Tracer, RecordSymbolicBranches

import uuid
from eth_utils import address

def manticore_runner(mcore: Manticore):
    mcore.run()
    mcore.finalize()
    
class MUIServicer(MUICore_pb2_grpc.ManticoreUIServicer):
    """Provides functionality for the methods set out in the protobuf spec"""

    def __init__(self):
        """Initializes the dict that keeps track of all created manticore instances, as well as avoid/find address set"""
        self.manticore_instances = {}
        self.avoid = set()
        self.find = set()

    def Start(
        self, cli_arguments: CLIArguments, context: _Context
    ) -> ManticoreInstance:
        """Starts a singular Manticore instance with the given CLI Arguments"""
        id = uuid.uuid4().hex
        print(cli_arguments.program_path)
        try:
            m = Manticore(
                cli_arguments.program_path,
                argv=None if not cli_arguments.binary_args else list(cli_arguments.binary_args),
                envp=None if not cli_arguments.envp else {key: val for key, val in [e.split() for e in cli_arguments.envp]},
                symbolic_files=None if not cli_arguments.symbolic_files else list(cli_arguments.symbolic_files),
                concrete_start='' if not cli_arguments.concrete_start else cli_arguments.concrete_start,
                stdin_size=265 if not cli_arguments.stdin_size else int(cli_arguments.stdin_size),
                **cli_arguments.additional_mcore_args,
            )

            def avoid_f(state: StateBase):
                state.abandon()

            for addr in self.avoid:
                m.add_hook(addr, avoid_f)

            def find_f(state: StateBase):
                bufs = state.solve_one_n_batched(state.input_symbols)
                for symbol, buf in zip(state.input_symbols, bufs):
                    print(f"{symbol.name}: {buf!r}\n")
                with m.locked_context() as context:
                    m.kill()
                state.abandon()

            for addr in self.find:
                m.add_hook(addr, find_f)
            
            m.register_plugin(InstructionCounter())
            m.register_plugin(Visited())
            m.register_plugin(Tracer())
            m.register_plugin(RecordSymbolicBranches())
            
            
            mthread = Thread(target=manticore_runner,args=(m,), daemon=True)
            mthread.start()
            self.manticore_instances[id] = (m,mthread)
            
        except Exception as e:
            print(e)
            raise e
            return ManticoreInstance()

        return ManticoreInstance(uuid=id)

    def Terminate(
        self, mcore_instance: ManticoreInstance, context: _Context
    ) -> TerminateResponse:
        """Terminates the specified Manticore instance."""
        if mcore_instance.uuid not in self.manticore_instances:
            return TerminateResponse(success=False)

        m, mthread = self.manticore_instances[mcore_instance.uuid]
        if m.is_killed() or not mthread.is_alive():
            return TerminateResponse(success=True)
        m.kill()
        return TerminateResponse(success=True)

    def TargetAddress(
        self, address_request: AddressRequest, context: _Context
    ) -> TargetResponse:
        """Sets addresses in the binary to find/avoid, or clears address status."""
        if address_request.mcore_instance.uuid not in self.manticore_instances:
            return TargetResponse(success=False)

        if address_request.type == AddressRequest.TargetType.FIND:
            self.find.add(address_request.address)
        elif address_request.type == AddressRequest.TargetType.AVOID:
            self.avoid.add(address_request.address)
        elif address_request.type == AddressRequest.TargetType.CLEAR:
            self.avoid.remove(address_request.address)
            self.find.remove(address_request.address)
        return TargetResponse(success=True)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    MUICore_pb2_grpc.add_ManticoreUIServicer_to_server(MUIServicer(), server)
    server.add_insecure_port("[::]:50010")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
