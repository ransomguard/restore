import io,json,threading,unittest
from types import SimpleNamespace
from unittest.mock import patch
from ransomguard import console_stream as c

class ConsoleStreamTests(unittest.TestCase):
    def test_review_stages_and_timing_keep_exact_audit_payload(self):
        for kind in ('review_suspend_requested', 'review_suspend_acknowledged',
                     'review_additional_file_evidence', 'review_required',
                     'response_path_timing'):
            payload={'score':0.76,'termination_confirmed':False}
            with patch.object(c,'emit') as emit:
                c.audit('runtime',kind,payload,'event','incident','now',True)
            emit.assert_called_once()
            runtime,channel,line=emit.call_args.args
            self.assertEqual((runtime,channel),('runtime','response'))
            item=json.loads(line)
            self.assertEqual(item['payload'],payload)
            self.assertEqual(item['storage_state'],'pending_commit')
            self.assertEqual(item['kind'],kind)

    def test_event_fanout_resolves_runtime_only_once_for_all_channels(self):
        c._runtime_digest.cache_clear()
        from pathlib import Path
        with patch.object(c.Path, 'resolve', return_value=Path('C:/runtime')) as resolve:
            first=c.pipe_name('runtime','kernel')
            for _ in range(100):
                self.assertEqual(c.pipe_name('runtime','kernel'),first)
                self.assertNotEqual(c.pipe_name('runtime','response'),first)
            self.assertEqual(resolve.call_count,1)
        c._runtime_digest.cache_clear()

    def test_kernel_event_emits_without_legacy_console_and_omits_command_line(self):
        event=SimpleNamespace(sequence=7,filetime=11,pid=42,kind='file_write',fields={'path':'one.txt','command_line':'SECRET'})
        with patch.object(c,'emit') as emit:c.kernel_event('runtime',event)
        runtime,channel,line=emit.call_args.args
        self.assertEqual((runtime,channel),('runtime','kernel'))
        self.assertEqual(json.loads(line)['sequence'],7)
        self.assertNotIn('SECRET',line)

    def test_idle_producer_does_not_block_another_connection(self):
        release=threading.Event();entered=threading.Event();out=io.BytesIO();lock=threading.Lock()
        class Connection:
            def __init__(self,idle=False):self.idle=idle;self.done=False
            def __enter__(self):return self
            def __exit__(self,*a):pass
            def recv_bytes(self,limit):
                if self.idle:entered.set();release.wait(3);raise EOFError
                if self.done:raise EOFError
                self.done=True;return b'{"kind":"restore_verified"}\n'
        idle=threading.Thread(target=c.copy_connection,args=(Connection(True),out,lock))
        idle.start()
        try:
            self.assertTrue(entered.wait(1))
            other=threading.Thread(target=c.copy_connection,args=(Connection(),out,lock));other.start();other.join(1)
            self.assertFalse(other.is_alive())
            self.assertIn(b'restore_verified',out.getvalue())
        finally:release.set();idle.join(2)

if __name__=='__main__':unittest.main()
