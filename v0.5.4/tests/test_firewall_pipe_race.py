import ctypes
import unittest
from unittest.mock import Mock, patch

from ransomguard.firewall_ipc import _WindowsPipeExchange


class PipeRaceTests(unittest.TestCase):
    def exchange(self):
        value = object.__new__(_WindowsPipeExchange)
        value.path = 'fixture'
        value.k = Mock()
        value.k.CreateFileW.return_value = 42
        value._transfer = Mock(side_effect=[2,b'{"success":true}\n'])
        return value

    def test_pipe_recreation_and_open_race_do_not_replay_request(self):
        x = self.exchange()
        x.k.WaitNamedPipeW.side_effect = [False,True,True]
        x.k.CreateFileW.side_effect = [ctypes.c_void_p(-1).value,42]
        with patch('ransomguard.firewall_ipc.C.get_last_error',side_effect=[2,231],create=True):
            self.assertEqual(x(b'{}',100),b'{"success":true}\n')
        self.assertEqual(x._transfer.call_count,2)
        x.k.CloseHandle.assert_called_once_with(42)

    def test_absent_daemon_has_bounded_deadline(self):
        x = self.exchange();x.k.WaitNamedPipeW.return_value = False
        with patch('ransomguard.firewall_ipc.C.get_last_error',return_value=2,create=True):
            with self.assertRaises(TimeoutError):x(b'{}',20)
        x._transfer.assert_not_called()

    def test_access_denied_is_not_retried(self):
        x = self.exchange();x.k.WaitNamedPipeW.return_value = False
        with patch('ransomguard.firewall_ipc.C.get_last_error',return_value=5,create=True):
            with self.assertRaises(OSError):x(b'{}',100)
        self.assertEqual(x.k.WaitNamedPipeW.call_count,1)

    def test_response_failure_never_resends_mutation(self):
        x = self.exchange();x.k.WaitNamedPipeW.return_value = True
        x._transfer.side_effect = [2,OSError(109,'broken pipe')]
        with self.assertRaises(OSError):x(b'{}',100)
        self.assertEqual(x.k.CreateFileW.call_count,1)
        self.assertEqual(x._transfer.call_count,2)
        x.k.CloseHandle.assert_called_once_with(42)
