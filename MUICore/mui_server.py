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
        
    def Start(self, cli_arguments: CLIArguments, context: _Context) -> ManticoreInstance:
        id = UUID(hexstr=uuid.uuid4().hex)
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