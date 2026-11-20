/* Complete one read-only overlapped IOCTL without repeatedly reacquiring the
 * Python GIL between Win32 calls. Cancellation always drains before return. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
__declspec(dllexport) DWORD __cdecl RgReadBatch(HANDLE device, DWORD code,
    void *buffer, DWORD capacity, DWORD timeout, DWORD *bytes, double *seconds)
{
    OVERLAPPED ov = {0};
    LARGE_INTEGER begin, end, frequency;
    DWORD error = ERROR_SUCCESS, wait, ignored;
    BOOL ok;
    *bytes = 0;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&begin);
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) return GetLastError();
    ok = DeviceIoControl(device, code, NULL, 0, buffer, capacity, bytes, &ov);
    if (!ok) {
        error = GetLastError();
        if (error == ERROR_IO_PENDING) {
            wait = WaitForSingleObject(ov.hEvent, timeout);
            if (wait != WAIT_OBJECT_0) {
                /* Even an unexpected wait failure must retain the stack and
                 * output buffer until the exact request has completed. */
                CancelIoEx(device, &ov);
                if (GetOverlappedResult(device, &ov, bytes, TRUE)) error = ERROR_SUCCESS;
                else error = GetLastError();
            } else if (GetOverlappedResult(device, &ov, bytes, FALSE)) {
                error = ERROR_SUCCESS;
            } else error = GetLastError();
        }
    }
    CloseHandle(ov.hEvent);
    QueryPerformanceCounter(&end);
    *seconds = (double)(end.QuadPart - begin.QuadPart) / frequency.QuadPart;
    if (!error && *bytes > capacity) { *bytes = 0; return ERROR_INVALID_DATA; }
    (void)ignored;
    return error;
}
