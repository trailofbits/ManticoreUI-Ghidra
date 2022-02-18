# MUI-Core
MUI-Core is a gRPC service that acts as a wrapper around  [Manticore](https://github.com/trailofbits/manticore), which will serve as the future of the [Manticore User Interface (MUI)](https://github.com/trailofbits/ManticoreUI) project. MUI-Core is designed to allow developers to create Manticore UI Plugins for different disassemblers easily, and to allow for Manticore itself to be done in the cloud/remotely.

# Usage
The MUI-Core server can be run via `python3 mui_server.py`. For most applications of MUI, in which a Python interpreter available or the required dependencies are not available, users can run the stand-alone `muicore_server` binary.

Currently, MUI-Core communicates only on `localhost:50010`. 

Your MUI Plugin will require the relevant gRPC client code. You can find out how to generate gRPC client code in your desired language from [the gRPC website](https://grpc.io/docs/languages/).

You may refer to the [Protobuf Specification](MUICore.proto) for information about the RPC services provided and the message types.

# Development
You may refer to [this commit](https://github.com/trailofbits/MUI-Ghidra/commit/468c8efbf949758633b9da839d377e09abfcf8d9) as an example of a feature being added to MUI Core. [codegen.sh](codegen.sh) will propagate the changes from `MUICore.proto` (current source is the proto file in the Ghidra plugin), and [build_binary.sh](muicore/build_binary.sh) will generate the `muicore_server` binary from the `mui_server.py` file (requires [`shiv`](https://github.com/linkedin/shiv)).
