#!/usr/bin/env python
# -*- Mode: Python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
# vim: ft=python ts=4 sts=4 sw=4 et ai

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Copyright 2018 Red Hat, Inc.

###############################################################################
# nmex.py contains helper functions used by some examples. The helper functions
# should be simple and independent, so that the user can extract them easily
# when modifying the example to his needs.
###############################################################################

def _sys_clock_gettime_ns_lazy():
    import ctypes

    class timespec(ctypes.Structure):
        _fields_ = [
                ('tv_sec', ctypes.c_long),
                ('tv_nsec', ctypes.c_long)
        ]

    librt = ctypes.CDLL('librt.so.1', use_errno=True)
    clock_gettime = librt.clock_gettime
    clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]

    t = timespec()
    def f(clock_id):
        if clock_gettime(clock_id, ctypes.pointer(t)) != 0:
            import os
            errno_ = ctypes.get_errno()
            raise OSError(errno_, os.strerror(errno_))
        return (t.tv_sec * 1000000000) + t.tv_nsec
    return f

_sys_clock_gettime_ns = None

# call POSIX clock_gettime() and return it as integer (in nanoseconds)
def sys_clock_gettime_ns(clock_id):
    global _sys_clock_gettime_ns
    if _sys_clock_gettime_ns is None:
        _sys_clock_gettime_ns = _sys_clock_gettime_ns_lazy()
    return _sys_clock_gettime_ns(clock_id)

def nm_boot_time_ns():
    # NetworkManager exposes some timestamps as CLOCK_BOOTTIME.
    # Try that first (number 7).
    try:
        return sys_clock_gettime_ns(7)
    except OSError as e:
        # On systems, where this is not available, fallback to
        # CLOCK_MONOTONIC (numeric 1).
        # That is what NetworkManager does as well.
        import errno
        if e.errno == errno.EINVAL:
            return sys_clock_gettime_ns(1)
        raise
def nm_boot_time_us():
    return nm_boot_time_ns() / 1000
def nm_boot_time_ms():
    return nm_boot_time_ns() / 1000000
def nm_boot_time_s():
    return nm_boot_time_ns() / 1000000000

###############################################################################
