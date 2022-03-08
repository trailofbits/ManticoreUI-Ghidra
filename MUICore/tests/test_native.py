import unittest

from muicore import mui_server
from muicore.MUICore_pb2 import *

from pathlib import Path
from uuid import UUID, uuid4
from shutil import rmtree
import glob
import time


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
            stime = time.time()
            while m.is_running():
                if (time.time() - stime) > 10:
                    time.sleep(1)

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

        self.assertTrue(mcore_instance.uuid in self.servicer.manticore_instances)

        mcore = self.servicer.manticore_instances[mcore_instance.uuid][0]
        self.assertTrue(Path(mcore.workspace).is_dir())

    def test_terminate_running_manticore(self):
        mcore_instance = self.servicer.Start(
            CLIArguments(program_path=self.binary_path), None
        )
        m, mthread = self.servicer.manticore_instances[mcore_instance.uuid]

        stime = time.time()
        while not m.is_running():
            if (time.time() - stime) > 5:
                self.fail(
                    f"Manticore instance {mcore_instance.uuid} failed to start running before timeout"
                )
            time.sleep(1)

        t_status = self.servicer.Terminate(mcore_instance, None)
        self.assertTrue(t_status.success)
        self.assertTrue(m.is_killed())

        stime = time.time()
        while m.is_running():
            if (time.time() - stime) > 10:
                self.fail(
                    f"Manticore instance {mcore_instance.uuid} failed to stop running before timeout"
                )
                time.sleep(1)

    def test_terminate_killed_manticore(self):
        mcore_instance = self.servicer.Start(
            CLIArguments(program_path=self.binary_path), None
        )
        m, mthread = self.servicer.manticore_instances[mcore_instance.uuid]
        m.kill()
        stime = time.time()
        while m.is_running():
            if (time.time() - stime) > 10:
                self.fail(
                    f"Manticore instance {mcore_instance.uuid} could not be killed before timeout"
                )
                time.sleep(1)

        t_status = self.servicer.Terminate(mcore_instance, None)

        self.assertTrue(t_status.success)

    def test_terminate_invalid_manticore(self):
        t_status = self.servicer.Terminate(ManticoreInstance(uuid=uuid4().hex), None)
        self.assertFalse(t_status.success)

    def test_get_message_list_running_manticore(self):
        mcore_instance = self.servicer.Start(
            CLIArguments(program_path=self.binary_path), None
        )
        m, mthread = self.servicer.manticore_instances[mcore_instance.uuid]

        stime = time.time()
        while m._log_queue.empty() and time.time() - stime < 5:
            time.sleep(1)
            if not m._log_queue.empty():
                deque_messages = list(m._log_queue)
                messages = self.servicer.GetMessageList(mcore_instance, None).messages
                for i in range(len(messages)):
                    self.assertEqual(messages[i].content, deque_messages[i])
                break

    def test_get_message_list_stopped_manticore(self):
        mcore_instance = self.servicer.Start(
            CLIArguments(program_path=self.binary_path), None
        )
        m, mthread = self.servicer.manticore_instances[mcore_instance.uuid]

        m.kill()
        stime = time.time()
        while m.is_running():
            if (time.time() - stime) > 10:
                self.fail(
                    f"Manticore instance {mcore_instance.uuid} could not be killed before timeout"
                )
                time.sleep(1)

        stime = time.time()
        while m._log_queue.empty() and time.time() - stime < 5:
            time.sleep(1)
            if not m._log_queue.empty():
                deque_messages = list(m._log_queue)
                messages = self.servicer.GetMessageList(mcore_instance, None).messages
                for i in range(len(messages)):
                    self.assertEqual(messages[i].content, deque_messages[i])
                break

    def test_get_message_list_invalid_manticore(self):
        message_list = self.servicer.GetMessageList(
            ManticoreInstance(uuid=uuid4().hex), None
        )
        self.assertEqual(len(message_list.messages), 1)
        self.assertEqual(
            message_list.messages[0].content, "Manticore instance not found!"
        )
