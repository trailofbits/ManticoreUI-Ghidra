from setuptools import setup, find_packages, Command


class GenerateCommand(Command):
    description = (
        "generates muicore server protobuf + grpc code from protobuf specification file"
    )
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        from grpc.tools import command

        command.build_package_protos(".")


shiv_args = {
    "output_file": "dist/muicore_server",
    "entry_point": None,
    "console_script": "muicore",
    "python": None,
    "site_packages": None,
    "build_id": None,
    "compressed": True,
    "compile_pyc": False,
    "extend_pythonpath": False,
    "reproducible": True,
    "no_modify": True,
    "preamble": None,
    "root": None,
    "pip_args": ["."],
}


class BuildBinaryCommand(Command):
    description = "packages and creates a muicore_server binary with shiv"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import shiv.cli
        import os

        if not os.path.exists("dist"):
            os.makedirs("dist")
        shiv.cli.main.callback(*shiv_args.values())


native_deps = [
    "capstone @ git+https://github.com/aquynh/capstone.git@1766485c0c32419e9a17d6ad31f9e218ef4f018f#subdirectory=bindings/python",
    "pyelftools",
    "unicorn==1.0.2",
]

setup(
    name="muicore",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "manticore @ git+https://github.com/trailofbits/manticore.git@chess",
        "grpcio",
    ]
    + native_deps,
    entry_points={
        "console_scripts": [
            "muicore=muicore.mui_server:main",
        ],
        "distutils.commands": ["generate = GenerateCommand"],
    },
    cmdclass={
        "generate": GenerateCommand,
        "build_binary": BuildBinaryCommand,
    },
)
