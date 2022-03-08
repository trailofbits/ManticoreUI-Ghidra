import unittest

from muicore import mui_server
from muicore.MUICore_pb2 import *

from pathlib import Path
from uuid import UUID
from shutil import rmtree
import glob


class MUICoreNativeTest(unittest.TestCase):
    def setUp(self):
        self.dirname = Path().absolute()
        self.binary_path = str(
            self.dirname / Path("binaries") / Path("arguments_linux_amd64")
        )
        self.servicer = mui_server.MUIServicer()

    def tearDown(self):
        for m, mthread in self.servicer.manticore_instances.values():
            m.kill()

    @classmethod
    def tearDownClass(cls):
        for f in glob.glob("mcore_*"):
            if Path(f).is_dir():
                rmtree(f, ignore_errors=True)

    def test_start_with_no_or_invalid_binary_path(self):
        with self.assertRaises(FileNotFoundError) as e:
            self.servicer.Start(CLIArguments(), None)

        expected_exception = "[Errno 2] No such file or directory: ''"

        self.assertEqual(str(e.exception), expected_exception)

        invalid_binary_path = str(
            self.dirname / Path("binaries") / Path("invalid_binary")
        )
        with self.assertRaises(FileNotFoundError) as e:
            self.servicer.Start(CLIArguments(program_path=invalid_binary_path), None)

        expected_exception = (
            f"[Errno 2] No such file or directory: '{invalid_binary_path}'"
        )

        self.assertEqual(str(e.exception), expected_exception)

    def test_start(self):
        mcore_instance = self.servicer.Start(
            CLIArguments(program_path=self.binary_path), None
        )

        try:
            UUID(mcore_instance.uuid)
        except ValueError:
            self.fail(
                "Start() returned ManticoreInstance with missing or malformed UUID"
            )

        assert mcore_instance.uuid in self.servicer.manticore_instances

        mcore = self.servicer.manticore_instances[mcore_instance.uuid][0]
        assert Path(mcore.workspace).is_dir()
