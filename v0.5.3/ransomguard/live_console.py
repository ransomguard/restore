"""Bounded live display in the actual collector process, never a second reader."""
import json, os, queue, threading, time
from pathlib import Path

class LiveConsole:
    def __init__(self, stream=None, capacity=256, control_path=None):
        self.stream=stream;self.queue=queue.Queue(capacity);self.stop=threading.Event()
        self.omitted=0;self.thread=None;self.control_thread=None;self.owned=False
        self.control_path=Path(control_path) if control_path else None
        self.control_mtime=None;self.next_control=0;self.show_own=False;self.own_filter=None
        self.visible=True;self.own_hidden=0
        from .observer_filter import ObserverOutboxFilter
        pid=os.environ.get('RANSOM0_UI_PROCESS_ID','')
        db=os.environ.get('RANSOM0_UI_DATABASE','')
        if pid.isdecimal() and db:self.own_filter=ObserverOutboxFilter(db,observer_pid=int(pid))
    def __enter__(self):
        try:
            result=self._open()
            self._status({'opened':True,'pid':os.getpid()})
            return result
        except (OSError, ValueError) as exc:
            self._status({'opened':False,'error':str(exc),'pid':os.getpid()})
            self.stop.set()
            if self.owned:
                if self.stream is not None:
                    self.stream.close()
                self.k.FreeConsole()
                self.k.SetConsoleCtrlHandler(None,False)
                self.owned=False
            return self
    def _status(self,data):
        try:Path(__file__).with_suffix('.status.json').write_text(json.dumps(data),encoding='utf-8')
        except OSError:pass
    def _open(self):
        if self.stream is None:
            import ctypes
            from ctypes import wintypes as W
            self.k=ctypes.WinDLL('kernel32',use_last_error=True)
            self.k.GetConsoleWindow.restype=W.HWND
            if not self.k.GetConsoleWindow():
                if not self.k.AllocConsole():raise ctypes.WinError(ctypes.get_last_error())
                self.owned=True
            self.k.GetStdHandle.argtypes=[W.DWORD];self.k.GetStdHandle.restype=W.HANDLE
            self.k.GetConsoleMode.argtypes=[W.HANDLE,ctypes.POINTER(W.DWORD)]
            self.k.SetConsoleMode.argtypes=[W.HANDLE,W.DWORD]
            handle=self.k.GetStdHandle(0xfffffff6);mode=W.DWORD()
            if self.k.GetConsoleMode(handle,ctypes.byref(mode)):
                self.k.SetConsoleMode(handle,(mode.value|0x80)&~0x40)
            self.title='RansomGuard LIVE kernel receiver - PID '+str(os.getpid())
            self.k.SetConsoleTitleW.argtypes=[W.LPCWSTR]
            self.k.SetConsoleTitleW(self.title)
            # Prevent an accidental Ctrl+C or close-button from killing protection.
            self.k.SetConsoleCtrlHandler(None,True)
            u=ctypes.WinDLL('user32',use_last_error=True)
            self.u=u
            u.IsWindowVisible.argtypes=[W.HWND];u.IsWindowVisible.restype=W.BOOL
            u.ShowWindowAsync.argtypes=[W.HWND,ctypes.c_int]
            self.hwnd=self.k.GetConsoleWindow()
            self.was_visible=bool(u.IsWindowVisible(self.hwnd))
            u.ShowWindowAsync(self.hwnd,5)
            u.GetSystemMenu.argtypes=[W.HWND,W.BOOL];u.GetSystemMenu.restype=W.HMENU
            u.DeleteMenu.argtypes=[W.HMENU,W.UINT,W.UINT]
            menu=u.GetSystemMenu(self.k.GetConsoleWindow(),False)
            if menu:u.DeleteMenu(menu,0xF060,0)
            self.stream=open('CONOUT$','w',encoding='utf8',buffering=1)
        self.control_thread=threading.Thread(target=self._control_loop,name='live-console-control',daemon=True)
        self.control_thread.start()
        self.thread=threading.Thread(target=self._run,name='live-console-output',daemon=True);self.thread.start();return self
    def offer(self,event):
        if self.stop.is_set():return
        if not self.show_own and self.own_filter and self.own_filter.matches(event):
            self.own_hidden+=1
            return
        fields=event.fields
        item={'source':'kernel_ioctl_live','sequence':event.sequence,'filetime':event.filetime,'pid':event.pid,'event':event.kind}
        for key in ('path','new_extension','image_path','matched_rule_id','operation_result'):
            if key in fields:item[key]=fields[key]
        if self.control_path:
            try:
                from .console_stream import emit
                emit(self.control_path.parent, 'kernel', json.dumps(item,ensure_ascii=False)+'\n')
            except Exception:
                pass # Optional display cannot stop protection.
        try:self.queue.put_nowait(item)
        except queue.Full:self.omitted+=1
    def _run(self):
        reported=0
        first=True
        try:
            while not self.stop.is_set():
                if self.omitted!=reported:
                    reported=self.omitted;self.stream.write('[DISPLAY ONLY] omitted='+str(reported)+'; collection continues independently\n')
                for _ in range(20):
                    try:item=self.queue.get_nowait()
                    except queue.Empty:break
                    self.stream.write(json.dumps(item,ensure_ascii=False)+'\n')
                    if first:
                        first=False
                        self._status({'opened':True,'pid':os.getpid(),'first_live_sequence':item['sequence'],
                                      'visible':bool(self.u.IsWindowVisible(self.hwnd)) if hasattr(self,'u') else None})
                self.stream.flush();self.stop.wait(.2)
        except (OSError,ValueError):
            pass # Output failure must not disable the independent control loop.
    def _control_loop(self):
        while not self.stop.is_set():
            self._controls()
            self.stop.wait(.2)
    def _controls(self):
        if not self.control_path or time.monotonic()<self.next_control:return
        self.next_control=time.monotonic()+1
        try:
            mtime=self.control_path.stat().st_mtime_ns
            if mtime==self.control_mtime:return
            value=json.loads(self.control_path.read_text(encoding='utf-8-sig'))
            if type(value.get('visible')) is not bool or type(value.get('showOwnDbEvents')) is not bool:return
            from .observer_filter import ObserverOutboxFilter
            pid=value.get('uiPid');db=value.get('uiDbPath')
            if type(pid) is int and pid>0 and isinstance(db,str) and db:
                self.own_filter=ObserverOutboxFilter(db,observer_pid=pid)
            self.show_own=value['showOwnDbEvents'];self.visible=value['visible']
            windows=[]
            actual=self.visible
            error=None
            if hasattr(self,'u'):
                windows=self._presentation_windows()
                if not windows:
                    error='No verified presentation window; visibility not confirmed'
                    actual=None
                else:
                    for hwnd,_,_ in windows:self.u.ShowWindowAsync(hwnd,5 if self.visible else 0)
                    deadline=time.monotonic()+2
                    while any(bool(self.u.IsWindowVisible(hwnd))!=self.visible for hwnd,_,_ in windows) and time.monotonic()<deadline:
                        self.stop.wait(.05)
                    actual=all(bool(self.u.IsWindowVisible(hwnd)) for hwnd,_,_ in windows) if self.visible else any(bool(self.u.IsWindowVisible(hwnd)) for hwnd,_,_ in windows)
            self.control_mtime=mtime if windows or not hasattr(self,'u') else None
            result={'opened':True,'pid':os.getpid(),'visible':actual,'requestId':value.get('requestId'),
                    'showOwnDbEvents':self.show_own,'own_hidden':self.own_hidden,'observedAt':time.time(),
                    'presentationWindows':[{'hwnd':int(h),'class':c,'title':t} for h,c,t in windows], 'candidates':getattr(self,'window_candidates',[]), 'error':error}
            self._status(result)
            target=self.control_path.with_name('console-display.status.json')
            temp=target.with_suffix('.tmp');temp.write_text(json.dumps(result),encoding='utf8');temp.replace(target)
        except (OSError,ValueError,TypeError):pass
    def _presentation_windows(self):
        """Only this collector's titled console; never unrelated terminal windows."""
        import ctypes as c
        from ctypes import wintypes as W
        u=self.u
        callback_type=c.WINFUNCTYPE(W.BOOL,W.HWND,W.LPARAM)
        u.EnumWindows.argtypes=[callback_type,W.LPARAM]
        u.GetClassNameW.argtypes=[W.HWND,W.LPWSTR,c.c_int]
        u.GetWindowTextW.argtypes=[W.HWND,W.LPWSTR,c.c_int]
        found=[]
        self.window_candidates=[]
        def visit(hwnd,param):
            cls=c.create_unicode_buffer(256);title=c.create_unicode_buffer(1024)
            u.GetClassNameW(hwnd,cls,256);u.GetWindowTextW(hwnd,title,1024)
            if 'RansomGuard LIVE' in title.value:self.window_candidates.append({'class':cls.value,'title':title.value})
            # Windows Terminal hosts a visible window separately from the pseudo-console handle.
            if cls.value in ('ConsoleWindowClass','CASCADIA_HOSTING_WINDOW_CLASS') and title.value.endswith(self.title):
                found.append((hwnd,cls.value,title.value))
            return True
        u.EnumWindows(callback_type(visit),0)
        return found
    def __exit__(self,*args):
        from .console_stream import close_outputs
        close_outputs()
        self.stop.set()
        if self.control_thread:self.control_thread.join(3)
        if self.thread:self.thread.join(1)
        if hasattr(self,'u') and not self.was_visible:
            self.u.ShowWindowAsync(self.hwnd,0)
        # Do not close a stream while a blocked output thread still owns it.
        if self.owned and (not self.thread or not self.thread.is_alive()):
            self.stream.close();self.k.FreeConsole();self.k.SetConsoleCtrlHandler(None,False)
