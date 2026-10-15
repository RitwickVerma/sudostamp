#!/usr/bin/env python3
"""Authenticate a user against one PAM service and report the result.

    pam_check.py <service> <user>        exit 0 = PAM_SUCCESS, 1 = anything else

The `test` step of install.sh uses this on a scratch service, so the new stack is proven
before /etc/pam.d/sudo is touched. It replaces pamtester, which Arch and openSUSE do not
package: libpam is called directly through ctypes, so this runs anywhere Python 3 and a
PAM library exist (Linux-PAM, and OpenPAM on macOS and FreeBSD).

Any prompt for input is answered with an empty string, so only a non-interactive module
(the phone) can make it succeed. Informational messages, such as pam_rssh's cue prompt,
are printed.
"""
import ctypes
import ctypes.util
import sys

PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON, PAM_ERROR_MSG, PAM_TEXT_INFO = 1, 2, 3, 4


class PamMessage(ctypes.Structure):
    _fields_ = [("msg_style", ctypes.c_int), ("msg", ctypes.c_char_p)]


class PamResponse(ctypes.Structure):
    # void*, not c_char_p: PAM free()s each response, so it must hold a pointer from the
    # C allocator, never one into Python-owned memory.
    _fields_ = [("resp", ctypes.c_void_p), ("resp_retcode", ctypes.c_int)]


CONV = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_int,
    ctypes.POINTER(ctypes.POINTER(PamMessage)),
    ctypes.POINTER(ctypes.POINTER(PamResponse)),
    ctypes.c_void_p,
)


class PamConv(ctypes.Structure):
    _fields_ = [("conv", CONV), ("appdata_ptr", ctypes.c_void_p)]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    service, user = sys.argv[1].encode(), sys.argv[2].encode()

    libpam = ctypes.CDLL(ctypes.util.find_library("pam") or "libpam.so.0")
    libc = ctypes.CDLL(ctypes.util.find_library("c"))
    libc.calloc.restype = ctypes.c_void_p
    libc.strdup.restype = ctypes.c_void_p
    libpam.pam_strerror.restype = ctypes.c_char_p

    @CONV
    def conv(n, msgs, resp, _):
        # PAM frees the responses itself, so they must come from the C allocator.
        arr = libc.calloc(n, ctypes.sizeof(PamResponse))
        out = ctypes.cast(arr, ctypes.POINTER(PamResponse))
        for i in range(n):
            # Linux-PAM and OpenPAM read this argument differently for n > 1; pam_rssh
            # sends one message per call, where both agree.
            m = msgs[i].contents
            text = (m.msg or b"").decode(errors="replace")
            if m.msg_style in (PAM_TEXT_INFO, PAM_ERROR_MSG):
                print("  pam: " + text, flush=True)
            out[i].resp = libc.strdup(b"")
            out[i].resp_retcode = 0
        resp[0] = out
        return 0

    # PAM keeps a pointer to this struct for the whole transaction: hold a reference so
    # Python cannot collect it mid-way.
    pam_conv = PamConv(conv, None)
    handle = ctypes.c_void_p()
    rc = libpam.pam_start(service, user, ctypes.byref(pam_conv), ctypes.byref(handle))
    if rc != 0:
        sys.exit("pam_start failed: %d" % rc)
    rc = libpam.pam_authenticate(handle, 0)
    msg = libpam.pam_strerror(handle, rc).decode()
    libpam.pam_end(handle, rc)
    print("  result: %s (%d)" % (msg, rc))
    sys.exit(0 if rc == 0 else 1)


if __name__ == "__main__":
    main()
