import setuptools

setuptools.setup(
    name='muicore',
    version='0.0.1',
    py_modules=["mui_server", "MUICore_pb2_grpc", "MUICore_pb2", "introspect_plugin"],
    entry_points={
        "console_scripts": [
            "muicore=mui_server:main",
        ]
    }
)