import unittest
from dataclasses import replace
from unittest.mock import patch
from ransomguard.ui_bridge import UiBestEffortPublisher
from ransomguard.observer_filter import _database_aliases
from tests.test_ui_bridge import MockSink, file_event


class UiStorageFanoutTests(unittest.TestCase):
    def test_only_exact_ui_pid_and_database_are_removed_from_fanout(self):
        with patch.dict('os.environ', {'RANSOM0_UI_DATABASE':'ui.sqlite', 'RANSOM0_UI_PROCESS_ID':'3256'}):
            sink=MockSink()
            publisher=UiBestEffortPublisher(sink)
        event=file_event()
        publisher._ui_storage._file_paths=_database_aliases(event.fields['path'])
        self.assertEqual(publisher.publish_event(event),'ui_storage_skipped')
        self.assertEqual(sink.messages,[])
        event=replace(event,pid=999)
        self.assertEqual(publisher.publish_event(event),'sent')
