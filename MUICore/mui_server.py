from concurrent import futures
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

import uuid
from eth_utils import address


class MUIServicer(MUICore_pb2_grpc.ManticoreUIServicer):
    """Provides functionality for the methods set out in the protobuf spec"""

    def __init__(self):
        """Initialises the dict that keeps track of all created manticore instances, as well as avoid/find address set"""
        self.manticore_instances = {}
        self.avoid = set()
        self.find = set()

    def Start(
        self, cli_arguments: CLIArguments, context: _Context
    ) -> ManticoreInstance:
        id = uuid.uuid4().hex
        try:
            m = Manticore.linux(
                cli_arguments.program_path,
                argv=list(cli_arguments.binary_args),
                envp={key: val for key, val in [e.split() for e in cli_arguments.envp]},
                symbolic_files=list(cli_arguments.symbolic_files),
                concrete_start=cli_arguments.concrete_start,
                stdin_size=0
                if len(cli_arguments.stdin_size) == 0
                else int(cli_arguments.stdin_size),
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

            m.run()
            self.manticore_instances[id] = m
        except Exception as e:
            print(e)
            raise e
            return ManticoreInstance()

        return ManticoreInstance(uuid=id)

    def Terminate(
        self, mcore_instance: ManticoreInstance, context: _Context
    ) -> TerminateResponse:
        if mcore_instance.uuid not in self.manticore_instances:
            return TerminateResponse(success=False)

        m = self.manticore_instances[mcore_instance.uuid]
        if m.is_killed():
            return TerminateResponse(success=True)
        m.kill()
        return TerminateResponse(success=True)

    def TargetAddress(
        self, address_request: AddressRequest, context: _Context
    ) -> TargetResponse:

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
    server.add_insecure_port("[::]:3216")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
