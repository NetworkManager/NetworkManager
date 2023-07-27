#!/usr/bin/env python
# coding: utf-8

from __future__ import print_function

###############################################################################
#
# This test starts NetworkManager stub service in a user D-Bus session,
# and runs nmcli against it. The output is recorded and compared to a pre-generated
# expected output (src/tests/client/test-client.check-on-disk/*.expected) which
# is also committed to git.
#
###############################################################################
#
# HOWTO: Regenerate output
#
# When adjusting the tests, or when making changes to nmcli that intentionally
# change the output, the expected output must be regenerated.
#
# For that, you'd setup your system correctly (see SETUP below) and then simply:
#
#  $ NM_TEST_REGENERATE=1 make check-local-tests-client
#    # Or `NM_TEST_REGENERATE=1 make check -j 10`
#  $ git diff ... ; git add ...
#    # The previous step regenerated the expected output. Review the changes
#    # and consider whether they are correct. Then commit the changes to git.
#
#   With meson, you can do
#     $ meson -Ddocs=true --prefix=/tmp/nm1 build
#     $ ninja -C build
#     $ ninja -C build install
#     $ NM_TEST_REGENERATE=1 ninja -C build test
#
# Beware that you need to install the sources, and beware to choose a prefix that doesn't
# mess up your system (see SETUP below).
#
# SETUP: For regenerating the output, the translations must work. First
# test whether the following works:
#
#  1) LANG=pl_PL.UTF-8 /usr/bin/nmcli --version
#    # Ensure that Polish output works for the system-installed nmcli.
#    # If not, you should ensure that `locale -a` reports the Polish
#    # locale. If that is not the case, how to enable the locale depends on
#    # your distro.
#    #
#    # On Debian, you might do:
#    #   sed -i 's/^# \(pl_PL.UTF-8 .*\)$/\1/p' /etc/locale.gen
#    #   locale-gen pl_PL.UTF-8
#    # On Fedora, you might install `glibc-langpack-pl` package.
#
#  2) LANG=pl_PL.UTF-8 ./src/nmcli/nmcli --version
#    # Ensure that the built nmcli has Polish locale working. If not,
#    # you probably need to first `make install` the application at the
#    # correct prefix. Take care to configure the build with the desired
#    # prefix, like `./configure --prefix=/opt/tmp`. Usually, you want to avoid
#    # using /usr as prefix, because that might overwrite files from your
#    # package management system.
#
###############################################################################
#
# Environment variables to configure test:

# (optional) The build dir. Optional, mainly used to find the nmcli binary (in case
# ENV_NM_TEST_CLIENT_NMCLI_PATH is not set.
ENV_NM_TEST_CLIENT_BUILDDIR = "NM_TEST_CLIENT_BUILDDIR"

# (optional) Path to nmcli. By default, it looks for nmcli in build dir.
# In particular, you can test also a nmcli binary installed somewhere else.
ENV_NM_TEST_CLIENT_NMCLI_PATH = "NM_TEST_CLIENT_NMCLI_PATH"

# (optional) Path to nm-cloud-setup. By default, it looks for nm-cloud-setup
# in build dir.
ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH = "NM_TEST_CLIENT_CLOUD_SETUP_PATH"

# (optional) The test also compares tranlsated output (l10n). This requires,
# that you first install the translation in the right place. So, by default,
# if a test for a translation fails, it will mark the test as skipped, and not
# fail the tests. Under the assumption, that the test cannot succeed currently.
# By setting NM_TEST_CLIENT_CHECK_L10N=1, you can force a failure of the test.
ENV_NM_TEST_CLIENT_CHECK_L10N = "NM_TEST_CLIENT_CHECK_L10N"

# Regenerate the .expected files. Instead of asserting, rewrite the files
# on disk with the expected output.
ENV_NM_TEST_REGENERATE = "NM_TEST_REGENERATE"

# whether the file location should include the line number. That is useful
# only for debugging, to correlate the expected output with the test.
# Obviously, since the expected output is commited to git without line numbers,
# you'd have to first NM_TEST_REGENERATE the test expected data, with line
# numbers enabled.
ENV_NM_TEST_WITH_LINENO = "NM_TEST_WITH_LINENO"

ENV_NM_TEST_ASAN_OPTIONS = "NM_TEST_ASAN_OPTIONS"
ENV_NM_TEST_LSAN_OPTIONS = "NM_TEST_LSAN_OPTIONS"
ENV_NM_TEST_UBSAN_OPTIONS = "NM_TEST_UBSAN_OPTIONS"

# Run nmcli under valgrind. If unset, we honor NMTST_USE_VALGRIND instead.
# Valgrind is always disabled, if NM_TEST_REGENERATE is enabled.
ENV_NM_TEST_VALGRIND = "NM_TEST_VALGRIND"

ENV_LIBTOOL = "LIBTOOL"

###############################################################################

import collections
import dbus
import dbus.mainloop.glib
import dbus.service
import errno
import fcntl
import io
import itertools
import os
import random
import re
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import gi

try:
    from gi.repository import GLib
except ImportError:
    GLib = None

try:
    gi.require_version("NM", "1.0")
except ValueError:
    NM = None
else:
    try:
        from gi.repository import NM
    except ImportError:
        NM = None

try:
    import pexpect
except ImportError:
    pexpect = None

try:
    from http.server import HTTPServer
    from http.server import BaseHTTPRequestHandler
    from http.client import HTTPConnection, HTTPResponse
except ImportError:
    HTTPServer = None


###############################################################################


class PathConfiguration:
    @staticmethod
    def srcdir():
        # this is the directory where the test script itself lies.
        # Based on this directory, we find other parts that we expect
        # in the source repository.
        return os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def top_srcdir():
        return os.path.abspath(PathConfiguration.srcdir() + "/../../..")

    @staticmethod
    def test_networkmanager_service_path():
        v = os.path.abspath(
            PathConfiguration.top_srcdir() + "/tools/test-networkmanager-service.py"
        )
        assert os.path.exists(v), 'Cannot find test server at "%s"' % (v)
        return v

    @staticmethod
    def test_cloud_meta_mock_path():
        v = os.path.abspath(
            PathConfiguration.top_srcdir() + "/tools/test-cloud-meta-mock.py"
        )
        assert os.path.exists(v), 'Cannot find cloud metadata mock server at "%s"' % (v)
        return v

    @staticmethod
    def canonical_script_filename():
        p = "src/tests/client/test-client.py"
        assert (PathConfiguration.top_srcdir() + "/" + p) == os.path.abspath(__file__)
        return p


###############################################################################

dbus_session_inited = False

_DEFAULT_ARG = object()
_UNSTABLE_OUTPUT = object()

###############################################################################


class Util:

    _signal_no_lookup = {
        1: "SIGHUP",
        2: "SIGINT",
        3: "SIGQUIT",
        4: "SIGILL",
        5: "SIGTRAP",
        6: "SIGABRT",
        8: "SIGFPE",
        9: "SIGKILL",
        11: "SIGSEGV",
        12: "SIGSYS",
        13: "SIGPIPE",
        14: "SIGALRM",
        15: "SIGTERM",
        16: "SIGURG",
        17: "SIGSTOP",
        18: "SIGTSTP",
        19: "SIGCONT",
        20: "SIGCHLD",
        21: "SIGTTIN",
        22: "SIGTTOU",
        23: "SIGPOLL",
        24: "SIGXCPU",
        25: "SIGXFSZ",
        26: "SIGVTALRM",
        27: "SIGPROF",
        30: "SIGUSR1",
        31: "SIGUSR2",
    }

    @classmethod
    def signal_no_to_str(cls, sig):
        s = cls._signal_no_lookup.get(sig, None)
        if s is None:
            return "<unknown %d>" % (sig)
        return s

    @staticmethod
    def python_has_version(major, minor=0):
        return sys.version_info[0] > major or (
            sys.version_info[0] == major and sys.version_info[1] >= minor
        )

    @staticmethod
    def is_string(s):
        if Util.python_has_version(3):
            t = str
        else:
            t = basestring
        return isinstance(s, t)

    @staticmethod
    def is_bool(s, defval=False):
        if s is None:
            return defval
        if isinstance(s, int):
            return s != 0
        if isinstance(s, str):
            if s.lower() in ["1", "y", "yes", "true", "on"]:
                return True
            if s.lower() in ["0", "n", "no", "false", "off"]:
                return False
        raise ValueError('Argument "%s" is not a boolean' % (s,))

    @staticmethod
    def as_bytes(s):
        if Util.is_string(s):
            return s.encode("utf-8")
        assert isinstance(s, bytes)
        return s

    @staticmethod
    def memoize_nullary(nullary_func):
        result = []

        def closure():
            if not result:
                result.append(nullary_func())
            return result[0]

        return closure

    _find_unsafe = re.compile(
        r"[^\w@%+=:,./-]", re.ASCII if sys.version_info[0] >= 3 else 0
    ).search

    @staticmethod
    def shlex_quote(s):
        # Reimplement shlex.quote().
        if Util.python_has_version(3, 3):
            return shlex.quote(s)
        if not s:
            return "''"
        if Util._find_unsafe(s) is None:
            return s
        return "'" + s.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def shlex_join(args):
        # Reimplement shlex.join()
        return " ".join(Util.shlex_quote(s) for s in args)

    @staticmethod
    def popen_wait(p, timeout=0):
        (res, b_stdout, b_stderr) = Util.popen_wait_read(
            p, timeout=timeout, read_std_pipes=False
        )
        return res

    @staticmethod
    def popen_wait_read(p, timeout=0, read_std_pipes=True):
        start = NM.utils_get_timestamp_msec()
        delay = 0.0005
        b_stdout = b""
        b_stderr = b""
        res = None
        while True:
            if read_std_pipes:
                b_stdout += Util.buffer_read(p.stdout)
                b_stderr += Util.buffer_read(p.stderr)
            if p.poll() is not None:
                res = p.returncode
                break
            if timeout == 0:
                break
            assert timeout > 0
            remaining = timeout - ((NM.utils_get_timestamp_msec() - start) / 1000.0)
            if remaining <= 0:
                break
            delay = min(delay * 2, remaining, 0.05)
            time.sleep(delay)
        return (res, b_stdout, b_stderr)

    @staticmethod
    def buffer_read(buf):
        b = b""
        while True:
            try:
                b1 = buf.read()
            except io.BlockingIOError:
                b1 = b""
            except IOError:
                b1 = b""
            if not b1:
                return b
            b += b1

    @staticmethod
    def buffer_set_nonblock(buf):
        fd = buf.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    @staticmethod
    def random_job(jobs):
        jobs = list(jobs)
        l = len(jobs)
        t = l * (l + 1) / 2
        while True:
            # we return a random jobs from the list, but the indexes at the front of
            # the list are more likely. The idea is, that those jobs were started first,
            # and are expected to complete first. As we poll, we want to check more frequently
            # on the elements at the beginning of the list...
            #
            # Let's assign probabilities with an arithmetic series.
            # That is, if there are 16 jobs, then the first gets weighted
            # with 16, the second with 15, then 14, and so on, until the
            # last has weight 1. That means, the first element is 16 times
            # more probable than the last.
            # Element at idx (starting with 0) is picked with probability
            #    1 / (l*(l+1)/2) * (l - idx)
            r = random.random() * t
            idx = 0
            rx = 0
            while True:
                rx += l - idx
                if rx >= r or idx == l - 1:
                    yield jobs[idx]
                    break
                idx += 1

    @staticmethod
    def iter_single(itr, min_num=1, max_num=1):
        itr = list(itr)
        n = 0
        v = None
        for c in itr:
            n += 1
            if n > 1:
                break
            v = c
        if n < min_num:
            raise AssertionError(
                "Expected at least %s elements, but %s found" % (min_num, n)
            )
        if n > max_num:
            raise AssertionError(
                "Expected at most %s elements, but %s found" % (max_num, n)
            )
        return v

    @staticmethod
    def file_read(filename):
        try:
            with open(filename, "rb") as f:
                return f.read()
        except:
            return None

    @staticmethod
    def file_read_expected(filename):
        results_expect = []
        content_expect = Util.file_read(filename)
        try:
            base_idx = 0
            size_prefix = "size: ".encode("utf8")
            while True:
                if not content_expect[base_idx : base_idx + 10].startswith(size_prefix):
                    raise Exception("Unexpected token")
                j = base_idx + len(size_prefix)
                i = j
                if Util.python_has_version(3, 0):
                    eol = ord("\n")
                else:
                    eol = "\n"
                while content_expect[i] != eol:
                    i += 1
                i = i + 1 + int(content_expect[j:i])
                results_expect.append(content_expect[base_idx:i])
                if len(content_expect) == i:
                    break
                base_idx = i
        except Exception as e:
            results_expect = None

        return content_expect, results_expect

    @staticmethod
    def _replace_text_match_join(split_arr, replacement):
        yield split_arr[0]
        for t in split_arr[1:]:
            yield (replacement,)
            yield t

    @staticmethod
    def ReplaceTextSimple(search, replacement):
        # This gives a function that can be used by Util.replace_text().
        # The function replaces an input bytes string @t. It must either return
        # a bytes string, a list containing bytes strings and/or 1-tuples (the
        # latter containing one bytes string).
        # The 1-tuple acts as a placeholder for atomic text, that cannot be replaced
        # a second time.
        #
        # Search for replace_text_fcn in Util.replace_text() where this is called.
        replacement = Util.as_bytes(replacement)

        if callable(search):
            search_fcn = search
        else:
            search_fcn = lambda: search

        def replace_fcn(t):
            assert isinstance(t, bytes)
            search_txt = search_fcn()
            if search_txt is None:
                return t
            search_txt = Util.as_bytes(search_txt)
            return Util._replace_text_match_join(t.split(search_txt), replacement)

        return replace_fcn

    @staticmethod
    def ReplaceTextRegex(pattern, replacement):
        # See ReplaceTextSimple.
        pattern = Util.as_bytes(pattern)
        replacement = Util.as_bytes(replacement)
        p = re.compile(pattern)
        return lambda t: Util._replace_text_match_join(p.split(t), replacement)

    @staticmethod
    def replace_text(text, replace_arr):
        if not replace_arr:
            return text
        needs_encode = Util.python_has_version(3) and Util.is_string(text)
        if needs_encode:
            text = text.encode("utf-8")
        text = [text]
        for replace_text_fcn in replace_arr:
            text2 = []
            for t in text:
                # tuples are markers for atomic strings. They won't be replaced a second
                # time.
                if not isinstance(t, tuple):
                    t = replace_text_fcn(t)
                if isinstance(t, bytes) or isinstance(t, tuple):
                    text2.append(t)
                else:
                    text2.extend(t)
            text = text2
        bb = b"".join([(t[0] if isinstance(t, tuple) else t) for t in text])
        if needs_encode:
            bb = bb.decode("utf-8")
        return bb

    @staticmethod
    def replace_text_sort_list(lst, replace_arr):
        lst = [(Util.replace_text(elem, replace_arr), elem) for elem in lst]
        lst = sorted(lst)
        lst = [tup[1] for tup in lst]
        return list(lst)

    @staticmethod
    def debug_dbus_interface():
        # this is for printf debugging, not used in actual code.
        os.system(
            "busctl --user --verbose call org.freedesktop.NetworkManager /org/freedesktop org.freedesktop.DBus.ObjectManager GetManagedObjects | cat"
        )

    @staticmethod
    def iter_nmcli_output_modes():
        for mode in [[], ["--mode", "tabular"], ["--mode", "multiline"]]:
            for fmt in [[], ["--pretty"], ["--terse"]]:
                for color in [[], ["--color", "yes"]]:
                    yield mode + fmt + color

    @staticmethod
    def valgrind_check_log(valgrind_log, logname):
        if valgrind_log is None:
            return

        fd, name = valgrind_log

        os.close(fd)

        if not os.path.isfile(name):
            raise Exception("valgrind log %s unexpectedly does not exist" % (name,))

        if os.path.getsize(name) != 0:
            out = subprocess.run(
                [
                    "sed",
                    "-e",
                    "/^--[0-9]\+-- WARNING: unhandled .* syscall: /,/^--[0-9]\+-- it at http.*\.$/d",
                    name,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if out.returncode != 0:
                raise Exception('Calling "sed" to search valgrind log failed')
            if out.stdout:
                print("valgrind log %s for %s is not empty:" % (name, logname))
                print("\n%s\n" % (out.stdout.decode("utf-8", errors="replace"),))
                raise Exception("valgrind log %s unexpectedly is not empty" % (name,))

        os.remove(name)

    @staticmethod
    def pexpect_expect_all(pexp, *pattern_list):
        # This will call "pexpect.expect()" on pattern_list,
        # expecting all entries to match exactly once, in any
        # order.
        pattern_list = list(pattern_list)
        while pattern_list:
            idx = pexp.expect(pattern_list)
            del pattern_list[idx]

    @staticmethod
    def skip_without_pexpect(_func=None):
        if _func is None:
            if pexpect is None:
                raise unittest.SkipTest("pexpect not available")
            return

        def f(*a, **kw):
            Util.skip_without_pexpect()
            _func(*a, **kw)

        return f

    @staticmethod
    def skip_without_dbus_session(_func=None):
        if _func is None:
            if not dbus_session_inited:
                raise unittest.SkipTest(
                    "Own D-Bus session for testing is not initialized. Do you have dbus-run-session available?"
                )
            return

        def f(*a, **kw):
            Util.skip_without_dbus_session()
            _func(*a, **kw)

        return f

    @staticmethod
    def skip_without_NM(_func=None):
        if _func is None:
            if NM is None:
                raise unittest.SkipTest(
                    "gi.NM is not available. Did you build with introspection?"
                )
            return

        def f(*a, **kw):
            Util.skip_without_NM()
            _func(*a, **kw)

        return f

    @staticmethod
    def cmd_create_env(
        lang="C",
        calling_num=None,
        fatal_warnings=_DEFAULT_ARG,
        extra_env=None,
    ):
        if lang == "C":
            language = ""
        elif lang == "de_DE.utf8":
            language = "de"
        elif lang == "pl_PL.UTF-8":
            language = "pl"
        else:
            raise AssertionError("invalid language %s" % (lang))

        env = {}
        for k in [
            "LD_LIBRARY_PATH",
            "DBUS_SESSION_BUS_ADDRESS",
            "LIBNM_CLIENT_DEBUG",
            "LIBNM_CLIENT_DEBUG_FILE",
        ]:
            val = os.environ.get(k, None)
            if val is not None:
                env[k] = val
        env["LANG"] = lang
        env["LANGUAGE"] = language
        env["LIBNM_USE_SESSION_BUS"] = "1"
        env["LIBNM_USE_NO_UDEV"] = "1"
        env["TERM"] = "linux"
        env["ASAN_OPTIONS"] = conf.get(ENV_NM_TEST_ASAN_OPTIONS)
        env["LSAN_OPTIONS"] = conf.get(ENV_NM_TEST_LSAN_OPTIONS)
        env["LBSAN_OPTIONS"] = conf.get(ENV_NM_TEST_UBSAN_OPTIONS)
        env["XDG_CONFIG_HOME"] = PathConfiguration.srcdir()
        if calling_num is not None:
            env["NM_TEST_CALLING_NUM"] = str(calling_num)
        if fatal_warnings is _DEFAULT_ARG or fatal_warnings:
            env["G_DEBUG"] = "fatal-warnings"
        if extra_env is not None:
            for k, v in extra_env.items():
                env[k] = v
        return env

    @staticmethod
    def cmd_create_argv(cmd_path, args, with_valgrind=None):

        if with_valgrind is None:
            with_valgrind = conf.get(ENV_NM_TEST_VALGRIND)

        valgrind_log = None
        cmd = conf.get(cmd_path)
        if with_valgrind:
            valgrind_log = tempfile.mkstemp(prefix="nm-test-client-valgrind.")
            argv = [
                "valgrind",
                "--quiet",
                "--error-exitcode=37",
                "--leak-check=full",
                "--gen-suppressions=all",
                (
                    "--suppressions="
                    + PathConfiguration.top_srcdir()
                    + "/valgrind.suppressions"
                ),
                "--num-callers=100",
                "--log-file=" + valgrind_log[1],
                cmd,
            ]
            libtool = conf.get(ENV_LIBTOOL)
            if libtool:
                argv = list(libtool) + ["--mode=execute"] + argv
        else:
            argv = [cmd]

        argv.extend(args)
        return argv, valgrind_log

    @staticmethod
    def cmd_call_pexpect(cmd_path, args, extra_env):
        argv, valgrind_log = Util.cmd_create_argv(cmd_path, args)
        env = Util.cmd_create_env(extra_env=extra_env)

        pexp = pexpect.spawn(argv[0], argv[1:], timeout=10, env=env)

        pexp.str_last_chars = 100000

        typ = collections.namedtuple("CallPexpect", ["pexp", "valgrind_log"])
        return typ(pexp, valgrind_log)

    @staticmethod
    def cmd_call_pexpect_nmcli(args, extra_env={}):
        extra_env = extra_env.copy()
        extra_env.update({"NO_COLOR": "1"})

        return Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_NMCLI_PATH,
            args,
            extra_env,
        )

    @staticmethod
    def get_nmcli_version():
        ver = NM.utils_version()
        micro = ver & 0xFF
        minor = (ver >> 8) & 0xFF
        major = ver >> 16
        return f"{major}.{minor}.{micro}"


###############################################################################


class Configuration:
    def __init__(self):
        self._values = {}

    def get(self, name):
        v = self._values.get(name, None)
        if name in self._values:
            return v
        if name == ENV_NM_TEST_CLIENT_BUILDDIR:
            v = os.environ.get(
                ENV_NM_TEST_CLIENT_BUILDDIR, PathConfiguration.top_srcdir()
            )
            if not os.path.isdir(v):
                raise Exception("Missing builddir. Set NM_TEST_CLIENT_BUILDDIR?")
        elif name == ENV_NM_TEST_CLIENT_NMCLI_PATH:
            v = os.environ.get(ENV_NM_TEST_CLIENT_NMCLI_PATH, None)
            if v is None:
                try:
                    v = os.path.abspath(
                        self.get(ENV_NM_TEST_CLIENT_BUILDDIR) + "/src/nmcli/nmcli"
                    )
                except:
                    pass
            if not os.path.exists(v):
                raise Exception("Missing nmcli binary. Set NM_TEST_CLIENT_NMCLI_PATH?")
        elif name == ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH:
            v = os.environ.get(ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH, None)
            if v is None:
                try:
                    v = os.path.abspath(
                        self.get(ENV_NM_TEST_CLIENT_BUILDDIR)
                        + "/src/nm-cloud-setup/nm-cloud-setup"
                    )
                except:
                    pass
            if not os.path.exists(v):
                raise Exception(
                    "Missing nm-cloud-setup binary. Set NM_TEST_CLIENT_CLOUD_SETUP_PATH?"
                )
        elif name == ENV_NM_TEST_CLIENT_CHECK_L10N:
            # if we test locales other than 'C', the output of nmcli depends on whether
            # nmcli can load the translations. Unfortunately, I cannot find a way to
            # make gettext use the po/*.gmo files from the build-dir.
            #
            # hence, such tests only work, if you also issue `make-install`
            #
            # Only by setting NM_TEST_CLIENT_CHECK_L10N=1, these tests are included
            # as well.
            v = Util.is_bool(os.environ.get(ENV_NM_TEST_CLIENT_CHECK_L10N, None))
        elif name == ENV_NM_TEST_REGENERATE:
            # in the "regenerate" mode, the tests will rewrite the files on disk against
            # which we assert. That is useful, if there are intentional changes and
            # we want to regenerate the expected output.
            v = Util.is_bool(os.environ.get(ENV_NM_TEST_REGENERATE, None))
        elif name == ENV_NM_TEST_WITH_LINENO:
            v = Util.is_bool(os.environ.get(ENV_NM_TEST_WITH_LINENO, None))
        elif name == ENV_NM_TEST_VALGRIND:
            if self.get(ENV_NM_TEST_REGENERATE):
                v = False
            else:
                v = os.environ.get(ENV_NM_TEST_VALGRIND, None)
                if v:
                    v = Util.is_bool(v)
                else:
                    v = Util.is_bool(os.environ.get("NMTST_USE_VALGRIND", None))
        elif name in [
            ENV_NM_TEST_ASAN_OPTIONS,
            ENV_NM_TEST_LSAN_OPTIONS,
            ENV_NM_TEST_UBSAN_OPTIONS,
        ]:
            v = os.environ.get(name, None)
            if v is None:
                if name == ENV_NM_TEST_ASAN_OPTIONS:
                    v = "detect_leaks=1"
                    # v += ' fast_unwind_on_malloc=false'
                elif name == ENV_NM_TEST_LSAN_OPTIONS:
                    v = ""
                elif name == ENV_NM_TEST_UBSAN_OPTIONS:
                    v = "print_stacktrace=1:halt_on_error=1"
                else:
                    assert False
        elif name == ENV_LIBTOOL:
            v = os.environ.get(name, None)
            if v is None:
                v = os.path.abspath(
                    os.path.dirname(self.get(ENV_NM_TEST_CLIENT_NMCLI_PATH))
                    + "/../../libtool"
                )
                if not os.path.isfile(v):
                    v = None
                else:
                    v = [v]
            elif not v:
                v = None
            else:
                v = shlex.split(v)
        else:
            raise Exception()
        self._values[name] = v
        return v


conf = Configuration()

###############################################################################


class NMStubServer:
    @staticmethod
    def _conn_get_main_object(conn):
        try:
            return conn.get_object(
                "org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager"
            )
        except:
            return None

    def __init__(self, seed, version=None):
        service_path = PathConfiguration.test_networkmanager_service_path()
        self._conn = dbus.SessionBus()
        env = os.environ.copy()
        env["NM_TEST_NETWORKMANAGER_SERVICE_SEED"] = seed
        if version is not None:
            env["NM_TEST_NETWORKMANAGER_SERVICE_VERSION"] = version
        else:
            env["NM_TEST_NETWORKMANAGER_SERVICE_VERSION"] = Util.get_nmcli_version()
        p = subprocess.Popen(
            [sys.executable, service_path], stdin=subprocess.PIPE, env=env
        )

        start = NM.utils_get_timestamp_msec()
        while True:
            if p.poll() is not None:
                p.stdin.close()
                if p.returncode == 77:
                    raise unittest.SkipTest(
                        "the stub service %s exited with status 77" % (service_path)
                    )
                raise Exception(
                    "the stub service %s exited unexpectedly" % (service_path)
                )
            nmobj = self._conn_get_main_object(self._conn)
            if nmobj is not None:
                break
            if (NM.utils_get_timestamp_msec() - start) >= 4000:
                p.stdin.close()
                p.kill()
                Util.popen_wait(p, 1)
                raise Exception(
                    "after starting stub service the D-Bus name was not claimed in time"
                )

        self._nmobj = nmobj
        self._nmiface = dbus.Interface(
            nmobj, "org.freedesktop.NetworkManager.LibnmGlibTest"
        )
        self._p = p

    def shutdown(self, kill_mode="random"):
        conn = self._conn
        p = self._p
        self._nmobj = None
        self._nmiface = None
        self._conn = None
        self._p = None

        # The test stub service watches stdin and will do a proper
        # shutdown when it closes. That means, to send signals about
        # going away.
        # On the other hand, just killing it will cause the process
        # from dropping off the bus.
        if kill_mode == "kill":
            p.kill()
        elif kill_mode == "stdin-close":
            p.stdin.close()
        else:
            assert kill_mode == "random"
            ops = [p.stdin.close, p.kill]
            random.shuffle(ops)
            ops[0]()
            r = random.random()
            if r < 0.75:
                if r < 0.5:
                    time.sleep(r * 0.2)
                ops[1]()

        if Util.popen_wait(p, 1) is None:
            raise Exception("Stub service did not exit in time")
        p.stdin.close()
        if self._conn_get_main_object(conn) is not None:
            raise Exception(
                "Stub service is not still here although it should shut down"
            )

    class _MethodProxy:
        def __init__(self, parent, method_name):
            self._parent = parent
            self._method_name = method_name

        def __call__(self, *args, **kwargs):
            dbus_iface = kwargs.pop("dbus_iface", None)
            if dbus_iface is None:
                dbus_iface = self._parent._nmiface
            method = dbus_iface.get_dbus_method(self._method_name)
            if kwargs:
                # for convenience, we allow the caller to specify arguments
                # as kwargs. In this case, we construct a a{sv} array as last argument.
                args = list(args)
                args.append(kwargs)
            return method(*args)

    def __getattr__(self, member):
        if not member.startswith("op_"):
            raise AttributeError(member)
        return self._MethodProxy(self, member[3:])

    def addConnection(self, connection, do_verify_strict=True):
        return self.op_AddConnection(connection, do_verify_strict)

    def findConnections(self, **kwargs):
        if kwargs:
            lst = self.op_FindConnections(**kwargs)
        else:
            lst = self.op_FindConnections({})
        return list([(str(elem[0]), str(elem[1]), str(elem[2])) for elem in lst])

    def findConnectionUuid(self, con_id, required=True):
        try:
            u = Util.iter_single(self.findConnections(con_id=con_id))[1]
            assert u, "Invalid uuid %s" % (u)
        except Exception as e:
            if not required:
                return None
            raise AssertionError(
                "Unexpectedly not found connection %s: %s" % (con_id, str(e))
            )
        return u

    def ReplaceTextConUuid(self, con_name, replacement):
        return Util.ReplaceTextSimple(
            Util.memoize_nullary(lambda: self.findConnectionUuid(con_name)),
            replacement,
        )

    def setProperty(self, path, propname, value, iface_name=None):
        if iface_name is None:
            iface_name = ""
        self.op_SetProperties([(path, [(iface_name, [(propname, value)])])])

    def addAndActivateConnection(
        self, connection, device, specific_object="", delay=None
    ):
        if delay is not None:
            self.op_SetActiveConnectionStateChangedDelay(device, delay)
        nm_iface = self._conn_get_main_object(self._conn)
        self.op_AddAndActivateConnection(
            connection, device, specific_object, dbus_iface=nm_iface
        )


###############################################################################


class AsyncProcess:
    def __init__(self, args, env, complete_cb, max_waittime_msec=20000):
        self._args = list(args)
        self._env = env
        self._complete_cb = complete_cb
        self._max_waittime_msec = max_waittime_msec

    def start(self):
        if not hasattr(self, "_p"):
            self._p_start_timestamp = NM.utils_get_timestamp_msec()
            self._p_stdout_buf = b""
            self._p_stderr_buf = b""
            self._p = subprocess.Popen(
                self._args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
            )
            Util.buffer_set_nonblock(self._p.stdout)
            Util.buffer_set_nonblock(self._p.stderr)

    def _timeout_remaining_time(self):
        # note that we call this during poll() and wait_and_complete().
        # we don't know the exact time when the process terminated,
        # so this is only approximately correct, if we call poll/wait
        # frequently.
        # Worst case, we will think that the process did not time out,
        # when in fact it was running longer than max-waittime.
        return self._max_waittime_msec - (
            NM.utils_get_timestamp_msec() - self._p_start_timestamp
        )

    def poll(self, timeout=0):
        self.start()

        (return_code, b_stdout, b_stderr) = Util.popen_wait_read(self._p, timeout)

        self._p_stdout_buf += b_stdout
        self._p_stderr_buf += b_stderr

        if return_code is None and self._timeout_remaining_time() <= 0:
            raise Exception(
                "process is still running after timeout: %s" % (" ".join(self._args))
            )
        return return_code

    def wait_and_complete(self):
        self.start()

        p = self._p
        self._p = None

        (return_code, b_stdout, b_stderr) = Util.popen_wait_read(
            p, max(0, self._timeout_remaining_time()) / 1000
        )
        (stdout, stderr) = (p.stdout.read(), p.stderr.read())
        p.stdout.close()
        p.stderr.close()

        stdout = self._p_stdout_buf + b_stdout + stdout
        stderr = self._p_stderr_buf + b_stderr + stderr
        del self._p_stdout_buf
        del self._p_stderr_buf

        if return_code is None:
            print(stdout)
            print(stderr)
            raise Exception(
                "process did not complete in time: %s" % (" ".join(self._args))
            )

        self._complete_cb(self, return_code, stdout, stderr)


###############################################################################


class NMTestContext:
    MAX_JOBS = 15

    def __init__(self, testMethodName):
        self.testMethodName = testMethodName
        self._calling_num = {}
        self._skip_test_for_l10n_diff = []
        self._async_jobs = []
        self.ctx_results = []
        self.srv = None

    def calling_num(self, calling_fcn):
        calling_num = self._calling_num.get(calling_fcn, 0) + 1
        self._calling_num[calling_fcn] = calling_num
        return calling_num

    def srv_start(self, srv_version=None):
        self.srv_shutdown()
        self.srv = NMStubServer(self.testMethodName, srv_version)

    def srv_shutdown(self):
        if self.srv is not None:
            srv = self.srv
            self.srv = None
            srv.shutdown()

    def async_start(self, wait_all=False):

        while True:

            while True:
                for async_job in list(self._async_jobs[0 : self.MAX_JOBS]):
                    async_job.start()
                # start up to MAX_JOBS jobs, but poll() and complete those
                # that are already exited. Retry, until there are no more
                # jobs to start, or until MAX_JOBS are running.
                jobs_running = []
                for async_job in list(self._async_jobs[0 : self.MAX_JOBS]):
                    if async_job.poll() is not None:
                        self._async_jobs.remove(async_job)
                        async_job.wait_and_complete()
                        continue
                    jobs_running.append(async_job)
                if len(jobs_running) >= len(self._async_jobs):
                    break
                if len(jobs_running) >= self.MAX_JOBS:
                    break

            if not jobs_running:
                return
            if not wait_all:
                return

            # in a loop, indefinitely poll the running jobs until we find one that
            # completes. Note that poll() itself will raise an exception if a
            # jobs times out.
            for async_job in Util.random_job(jobs_running):
                if async_job.poll(timeout=0.03) is not None:
                    self._async_jobs.remove(async_job)
                    async_job.wait_and_complete()
                    break

    def async_wait(self):
        return self.async_start(wait_all=True)

    def async_append_job(self, async_job):
        self._async_jobs.append(async_job)

    def run_post(self):

        self.async_wait()

        self.srv_shutdown()

        self._calling_num = None

        results = self.ctx_results
        self.ctx_results = None

        if len(results) == 0:
            return

        skip_test_for_l10n_diff = self._skip_test_for_l10n_diff
        self._skip_test_for_l10n_diff = None

        filename = os.path.abspath(
            PathConfiguration.srcdir()
            + "/test-client.check-on-disk/"
            + self.testMethodName
            + ".expected"
        )

        regenerate = conf.get(ENV_NM_TEST_REGENERATE)

        content_expect, results_expect = Util.file_read_expected(filename)

        if results_expect is None:
            if not regenerate:
                self.fail(
                    "Failed to parse expected file '%s'. Let the test write the file by rerunning with NM_TEST_REGENERATE=1"
                    % (filename)
                )
        else:
            for i in range(0, min(len(results_expect), len(results))):
                n = results[i]
                if results_expect[i] == n["content"]:
                    continue
                if regenerate:
                    continue
                if n["ignore_l10n_diff"]:
                    skip_test_for_l10n_diff.append(n["test_name"])
                    continue
                print(
                    "\n\n\nThe file '%s' does not have the expected content:"
                    % (filename)
                )
                print("ACTUAL OUTPUT:\n[[%s]]\n" % (n["content"]))
                print("EXPECT OUTPUT:\n[[%s]]\n" % (results_expect[i]))
                print(
                    "Let the test write the file by rerunning with NM_TEST_REGENERATE=1"
                )
                print(
                    "See howto in %s for details.\n"
                    % (PathConfiguration.canonical_script_filename())
                )
                sys.stdout.flush()
                self.fail(
                    "Unexpected output of command, expected %s. Rerun test with NM_TEST_REGENERATE=1 to regenerate files"
                    % (filename)
                )
            if len(results_expect) != len(results):
                if not regenerate:
                    print(
                        "\n\n\nThe number of tests in %s does not match the expected content (%s vs %s):"
                        % (filename, len(results_expect), len(results))
                    )
                    if len(results_expect) < len(results):
                        print(
                            "ACTUAL OUTPUT:\n[[%s]]\n"
                            % (results[len(results_expect)]["content"])
                        )
                    else:
                        print(
                            "EXPECT OUTPUT:\n[[%s]]\n" % (results_expect[len(results)])
                        )
                    print(
                        "Let the test write the file by rerunning with NM_TEST_REGENERATE=1"
                    )
                    print(
                        "See howto in %s for details.\n"
                        % (PathConfiguration.canonical_script_filename())
                    )
                    sys.stdout.flush()
                    self.fail(
                        "Unexpected output of command, expected %s. Rerun test with NM_TEST_REGENERATE=1 to regenerate files"
                        % (filename)
                    )

        if regenerate:
            content_new = b"".join([r["content"] for r in results])
            if content_new != content_expect:
                try:
                    with open(filename, "wb") as content_file:
                        content_file.write(content_new)
                except Exception as e:
                    self.fail("Failure to write '%s': %s" % (filename, e))

        if skip_test_for_l10n_diff:
            # nmcli loads translations from the installation path. This failure commonly
            # happens because you did not install the binary in the --prefix, before
            # running the test. Hence, translations are not available or differ.
            raise unittest.SkipTest(
                "Skipped asserting for localized tests %s. Set NM_TEST_CLIENT_CHECK_L10N=1 to force fail."
                % (",".join(skip_test_for_l10n_diff))
            )


###############################################################################


class TestNmcli(unittest.TestCase):
    def setUp(self):
        Util.skip_without_dbus_session()
        Util.skip_without_NM()
        self.ctx = NMTestContext(self._testMethodName)

    def call_nmcli_l(
        self,
        args,
        check_on_disk=_DEFAULT_ARG,
        fatal_warnings=_DEFAULT_ARG,
        expected_returncode=_DEFAULT_ARG,
        expected_stdout=_DEFAULT_ARG,
        expected_stderr=_DEFAULT_ARG,
        replace_stdout=None,
        replace_stderr=None,
        replace_cmd=None,
        sort_lines_stdout=False,
        extra_env=None,
        sync_barrier=False,
    ):
        frame = sys._getframe(1)
        for lang in ["C", "pl"]:
            self._call_nmcli(
                args,
                lang,
                check_on_disk,
                fatal_warnings,
                expected_returncode,
                expected_stdout,
                expected_stderr,
                replace_stdout,
                replace_stderr,
                replace_cmd,
                sort_lines_stdout,
                extra_env,
                sync_barrier,
                frame,
            )

    def call_nmcli(
        self,
        args,
        langs=None,
        lang=None,
        check_on_disk=_DEFAULT_ARG,
        fatal_warnings=_DEFAULT_ARG,
        expected_returncode=_DEFAULT_ARG,
        expected_stdout=_DEFAULT_ARG,
        expected_stderr=_DEFAULT_ARG,
        replace_stdout=None,
        replace_stderr=None,
        replace_cmd=None,
        sort_lines_stdout=False,
        extra_env=None,
        sync_barrier=None,
    ):

        frame = sys._getframe(1)

        if langs is not None:
            assert lang is None
        else:
            if lang is None:
                lang = "C"
            langs = [lang]

        if sync_barrier is None:
            sync_barrier = len(langs) == 1

        for lang in langs:
            self._call_nmcli(
                args,
                lang,
                check_on_disk,
                fatal_warnings,
                expected_returncode,
                expected_stdout,
                expected_stderr,
                replace_stdout,
                replace_stderr,
                replace_cmd,
                sort_lines_stdout,
                extra_env,
                sync_barrier,
                frame,
            )

    def _call_nmcli(
        self,
        args,
        lang,
        check_on_disk,
        fatal_warnings,
        expected_returncode,
        expected_stdout,
        expected_stderr,
        replace_stdout,
        replace_stderr,
        replace_cmd,
        sort_lines_stdout,
        extra_env,
        sync_barrier,
        frame,
    ):

        if sync_barrier:
            self.ctx.async_wait()

        calling_fcn = frame.f_code.co_name
        calling_num = self.ctx.calling_num(calling_fcn)

        test_name = "%s-%03d" % (calling_fcn, calling_num)

        # we cannot use frame.f_code.co_filename directly, because it might be different depending
        # on where the file lies and which is CWD. We still want to give the location of
        # the file, so that the user can easier find the source (when looking at the .expected files)
        self.assertTrue(
            os.path.abspath(frame.f_code.co_filename).endswith(
                "/" + PathConfiguration.canonical_script_filename()
            )
        )

        if conf.get(ENV_NM_TEST_WITH_LINENO):
            calling_location = "%s:%d:%s()/%d" % (
                PathConfiguration.canonical_script_filename(),
                frame.f_lineno,
                frame.f_code.co_name,
                calling_num,
            )
        else:
            calling_location = "%s:%s()/%d" % (
                PathConfiguration.canonical_script_filename(),
                frame.f_code.co_name,
                calling_num,
            )

        if lang is None or lang == "C":
            lang = "C"
        elif lang == "de":
            lang = "de_DE.utf8"
        elif lang == "pl":
            lang = "pl_PL.UTF-8"
        else:
            self.fail("invalid language %s" % (lang))

        # Running under valgrind is not yet supported for those tests.
        args, valgrind_log = Util.cmd_create_argv(
            ENV_NM_TEST_CLIENT_NMCLI_PATH, args, with_valgrind=False
        )

        assert valgrind_log is None

        if replace_stdout is not None:
            replace_stdout = list(replace_stdout)
        if replace_stderr is not None:
            replace_stderr = list(replace_stderr)
        if replace_cmd is not None:
            replace_cmd = list(replace_cmd)

        if check_on_disk is _DEFAULT_ARG:
            check_on_disk = (
                expected_returncode is _DEFAULT_ARG
                and (
                    expected_stdout is _DEFAULT_ARG
                    or expected_stdout is _UNSTABLE_OUTPUT
                )
                and (
                    expected_stderr is _DEFAULT_ARG
                    or expected_stderr is _UNSTABLE_OUTPUT
                )
            )
        if expected_returncode is _DEFAULT_ARG:
            expected_returncode = None
        if expected_stdout is _DEFAULT_ARG:
            expected_stdout = None
        if expected_stderr is _DEFAULT_ARG:
            expected_stderr = None

        results_idx = len(self.ctx.ctx_results)
        self.ctx.ctx_results.append(None)

        def complete_cb(async_job, returncode, stdout, stderr):

            if expected_stdout is _UNSTABLE_OUTPUT:
                stdout = "<UNSTABLE OUTPUT>".encode("utf-8")
            else:
                stdout = Util.replace_text(stdout, replace_stdout)

            if expected_stderr is _UNSTABLE_OUTPUT:
                stderr = "<UNSTABLE OUTPUT>".encode("utf-8")
            else:
                stderr = Util.replace_text(stderr, replace_stderr)

            if sort_lines_stdout:
                stdout = b"\n".join(sorted(stdout.split(b"\n")))

            ignore_l10n_diff = lang != "C" and not conf.get(
                ENV_NM_TEST_CLIENT_CHECK_L10N
            )

            if expected_stderr is not None and expected_stderr is not _UNSTABLE_OUTPUT:
                if expected_stderr != stderr:
                    if ignore_l10n_diff:
                        self._skip_test_for_l10n_diff.append(test_name)
                    else:
                        self.assertEqual(expected_stderr, stderr)
            if expected_stdout is not None and expected_stdout is not _UNSTABLE_OUTPUT:
                if expected_stdout != stdout:
                    if ignore_l10n_diff:
                        self._skip_test_for_l10n_diff.append(test_name)
                    else:
                        self.assertEqual(expected_stdout, stdout)
            if expected_returncode is not None:
                self.assertEqual(expected_returncode, returncode)

            if fatal_warnings is _DEFAULT_ARG:
                if expected_returncode != -5:
                    self.assertNotEqual(returncode, -5)
            elif fatal_warnings:
                if expected_returncode is None:
                    self.assertEqual(returncode, -5)

            if check_on_disk:
                cmd = "$NMCLI %s" % (Util.shlex_join(args[1:]),)
                cmd = Util.replace_text(cmd, replace_cmd)

                if returncode < 0:
                    returncode_str = "%d (SIGNAL %s)" % (
                        returncode,
                        Util.signal_no_to_str(-returncode),
                    )
                else:
                    returncode_str = "%d" % (returncode)

                content = (
                    ("location: %s\n" % (calling_location)).encode("utf8")
                    + ("cmd: %s\n" % (cmd)).encode("utf8")
                    + ("lang: %s\n" % (lang)).encode("utf8")
                    + ("returncode: %s\n" % (returncode_str)).encode("utf8")
                )
                if len(stdout) > 0:
                    content += (
                        ("stdout: %d bytes\n>>>\n" % (len(stdout))).encode("utf8")
                        + stdout
                        + "\n<<<\n".encode("utf8")
                    )
                if len(stderr) > 0:
                    content += (
                        ("stderr: %d bytes\n>>>\n" % (len(stderr))).encode("utf8")
                        + stderr
                        + "\n<<<\n".encode("utf8")
                    )
                content = ("size: %s\n" % (len(content))).encode("utf8") + content

                self.ctx.ctx_results[results_idx] = {
                    "test_name": test_name,
                    "ignore_l10n_diff": ignore_l10n_diff,
                    "content": content,
                }

        env = Util.cmd_create_env(lang, calling_num, fatal_warnings, extra_env)
        async_job = AsyncProcess(args=args, env=env, complete_cb=complete_cb)

        self.ctx.async_append_job(async_job)

        self.ctx.async_start(wait_all=sync_barrier)

    def nm_test(func):
        def f(self):
            self.ctx.srv_start()
            func(self)
            self.ctx.run_post()

        return f

    def nm_test_no_dbus(func):
        def f(self):
            func(self)
            self.ctx.run_post()

        return f

    def init_001(self):
        self.ctx.srv.op_AddObj("WiredDevice", iface="eth0")
        self.ctx.srv.op_AddObj("WiredDevice", iface="eth1")
        self.ctx.srv.op_AddObj("WifiDevice", iface="wlan0")
        self.ctx.srv.op_AddObj("WifiDevice", iface="wlan1")

        # add another device with an identical ifname. The D-Bus API itself
        # does not enforce the ifnames are unique.
        self.ctx.srv.op_AddObj("WifiDevice", ident="wlan1/x", iface="wlan1")

        self.ctx.srv.op_AddObj("WifiAp", device="wlan0", rsnf=0x0)

        self.ctx.srv.op_AddObj("WifiAp", device="wlan0")

        NM_AP_FLAGS = getattr(NM, "80211ApSecurityFlags")
        rsnf = 0x0
        rsnf = rsnf | NM_AP_FLAGS.PAIR_TKIP
        rsnf = rsnf | NM_AP_FLAGS.PAIR_CCMP
        rsnf = rsnf | NM_AP_FLAGS.GROUP_TKIP
        rsnf = rsnf | NM_AP_FLAGS.GROUP_CCMP
        rsnf = rsnf | NM_AP_FLAGS.KEY_MGMT_SAE
        self.ctx.srv.op_AddObj("WifiAp", device="wlan0", wpaf=0x0, rsnf=rsnf)

        self.ctx.srv.op_AddObj("WifiAp", device="wlan1")

        self.ctx.srv.addConnection(
            {"connection": {"type": "802-3-ethernet", "id": "con-1"}}
        )

    @nm_test
    def test_001(self):

        self.call_nmcli_l([])

        self.call_nmcli_l(
            ["-f", "AP", "-mode", "multiline", "-p", "d", "show", "wlan0"]
        )

        self.call_nmcli_l(["c", "s"])

        self.call_nmcli_l(["bogus", "s"])

        for mode in Util.iter_nmcli_output_modes():
            self.call_nmcli_l(mode + ["general", "permissions"])

    @nm_test
    def test_002(self):
        self.init_001()

        self.call_nmcli_l(["d"])

        self.call_nmcli_l(["-f", "all", "d"])

        self.call_nmcli_l([])

        self.call_nmcli_l(["-f", "AP", "-mode", "multiline", "d", "show", "wlan0"])
        self.call_nmcli_l(
            ["-f", "AP", "-mode", "multiline", "-p", "d", "show", "wlan0"]
        )
        self.call_nmcli_l(
            ["-f", "AP", "-mode", "multiline", "-t", "d", "show", "wlan0"]
        )
        self.call_nmcli_l(["-f", "AP", "-mode", "tabular", "d", "show", "wlan0"])
        self.call_nmcli_l(["-f", "AP", "-mode", "tabular", "-p", "d", "show", "wlan0"])
        self.call_nmcli_l(["-f", "AP", "-mode", "tabular", "-t", "d", "show", "wlan0"])

        self.call_nmcli_l(["-f", "ALL", "d", "wifi"])

        self.call_nmcli_l(["c"])

        self.call_nmcli_l(["c", "s", "con-1"])

    @nm_test
    def test_003(self):
        con_gsm_list = [
            ("con-gsm1", "xyz.con-gsm1"),
            ("con-gsm2", ""),
            ("con-gsm3", " "),
        ]

        self.init_001()

        replace_uuids = []

        replace_uuids.append(
            self.ctx.srv.ReplaceTextConUuid(
                "con-xx1", "UUID-con-xx1-REPLACED-REPLACED-REPLA"
            )
        )

        self.call_nmcli(
            ["c", "add", "type", "ethernet", "ifname", "*", "con-name", "con-xx1"],
            replace_stdout=replace_uuids,
        )

        self.call_nmcli_l(["c", "s"], replace_stdout=replace_uuids)

        for con_name, apn in con_gsm_list:

            replace_uuids.append(
                self.ctx.srv.ReplaceTextConUuid(
                    con_name, "UUID-" + con_name + "-REPLACED-REPLACED-REPL"
                )
            )

            self.call_nmcli(
                [
                    "connection",
                    "add",
                    "type",
                    "gsm",
                    "autoconnect",
                    "no",
                    "con-name",
                    con_name,
                    "ifname",
                    "*",
                    "apn",
                    apn,
                    "serial.baud",
                    "5",
                    "serial.send-delay",
                    "100",
                    "serial.pari",
                    "1",
                    "ipv4.dns-options",
                    " ",
                ],
                replace_stdout=replace_uuids,
            )

        replace_uuids.append(
            self.ctx.srv.ReplaceTextConUuid(
                "ethernet", "UUID-ethernet-REPLACED-REPLACED-REPL"
            )
        )

        self.call_nmcli(
            ["c", "add", "type", "ethernet", "ifname", "*"],
            replace_stdout=replace_uuids,
        )

        self.call_nmcli_l(["c", "s"], replace_stdout=replace_uuids)

        self.call_nmcli_l(["-f", "ALL", "c", "s"], replace_stdout=replace_uuids)

        self.call_nmcli_l(
            ["--complete-args", "-f", "ALL", "c", "s", ""],
            replace_stdout=replace_uuids,
            sort_lines_stdout=True,
        )

        for con_name, apn in con_gsm_list:
            self.call_nmcli_l(["con", "s", con_name], replace_stdout=replace_uuids)
            self.call_nmcli_l(
                ["-g", "all", "con", "s", con_name], replace_stdout=replace_uuids
            )

        # activate the same profile on multiple devices. Our stub-implmentation
        # is fine with that... although NetworkManager service would reject
        # such a configuration by deactivating the profile first. But note that
        # that is only an internal behavior of NetworkManager service. The D-Bus
        # API perfectly allows for one profile to be active multiple times. Also
        # note, that there is always a short time where one profile goes down,
        # while another is activating. Hence, while real NetworkManager commonly
        # does not allow that multiple profiles *stay* connected at the same
        # time, there is always the possibility that a profile is activating/active
        # on a device, while also activating/deactivating in parallel.
        for dev in ["eth0", "eth1"]:
            self.call_nmcli(["con", "up", "ethernet", "ifname", dev])

            self.call_nmcli_l(["con"], replace_stdout=replace_uuids)

            self.call_nmcli_l(["-f", "ALL", "con"], replace_stdout=replace_uuids)

            self.call_nmcli_l(
                ["-f", "ALL", "con", "s", "-a"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(
                ["-f", "ACTIVE-PATH,DEVICE,UUID", "con", "s", "-act"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                ["-f", "UUID,NAME", "con", "s", "--active"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                ["-f", "ALL", "con", "s", "ethernet"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(
                ["-f", "GENERAL.STATE", "con", "s", "ethernet"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(["con", "s", "ethernet"], replace_stdout=replace_uuids)

            self.call_nmcli_l(
                ["-f", "ALL", "dev", "status"], replace_stdout=replace_uuids
            )

            # test invalid call ('s' abbrevates 'status' and not 'show'
            self.call_nmcli_l(
                ["-f", "ALL", "dev", "s", "eth0"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(
                ["-f", "ALL", "dev", "show", "eth0"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(
                ["-f", "ALL", "-t", "dev", "show", "eth0"], replace_stdout=replace_uuids
            )

        self.ctx.async_wait()

        self.ctx.srv.setProperty(
            "/org/freedesktop/NetworkManager/ActiveConnection/1",
            "State",
            dbus.UInt32(NM.ActiveConnectionState.DEACTIVATING),
        )

        self.call_nmcli_l([], replace_stdout=replace_uuids)

        for i in [0, 1]:
            if i == 1:
                self.ctx.async_wait()
                self.ctx.srv.op_ConnectionSetVisible(False, con_id="ethernet")

            for mode in Util.iter_nmcli_output_modes():
                self.call_nmcli_l(
                    mode + ["-f", "ALL", "con"], replace_stdout=replace_uuids
                )

                self.call_nmcli_l(
                    mode + ["-f", "UUID,TYPE", "con"], replace_stdout=replace_uuids
                )

                self.call_nmcli_l(
                    mode + ["con", "s", "ethernet"], replace_stdout=replace_uuids
                )

                self.call_nmcli_l(
                    mode
                    + ["c", "s", "/org/freedesktop/NetworkManager/ActiveConnection/1"],
                    replace_stdout=replace_uuids,
                )

                self.call_nmcli_l(
                    mode + ["-f", "all", "dev", "show", "eth0"],
                    replace_stdout=replace_uuids,
                )

    @nm_test
    def test_004(self):
        self.init_001()

        replace_uuids = []

        replace_uuids.append(
            self.ctx.srv.ReplaceTextConUuid(
                "con-xx1", "UUID-con-xx1-REPLACED-REPLACED-REPLA"
            )
        )

        self.call_nmcli(
            [
                "c",
                "add",
                "type",
                "wifi",
                "ifname",
                "*",
                "ssid",
                "foobar",
                "con-name",
                "con-xx1",
            ],
            replace_stdout=replace_uuids,
        )

        self.call_nmcli(["connection", "mod", "con-xx1", "ip.gateway", ""])
        self.call_nmcli(
            ["connection", "mod", "con-xx1", "ipv4.gateway", "172.16.0.1"], lang="pl"
        )
        self.call_nmcli(["connection", "mod", "con-xx1", "ipv6.gateway", "::99"])
        self.call_nmcli(["connection", "mod", "con-xx1", "802.abc", ""])
        self.call_nmcli(["connection", "mod", "con-xx1", "802-11-wireless.band", "a"])
        self.call_nmcli(
            [
                "connection",
                "mod",
                "con-xx1",
                "ipv4.addresses",
                "192.168.77.5/24",
                "ipv4.routes",
                "2.3.4.5/32 192.168.77.1",
                "ipv6.addresses",
                "1:2:3:4::6/64",
                "ipv6.routes",
                "1:2:3:4:5:6::5/128",
            ]
        )
        self.call_nmcli_l(["con", "s", "con-xx1"], replace_stdout=replace_uuids)

        self.ctx.async_wait()

        replace_uuids.append(
            self.ctx.srv.ReplaceTextConUuid(
                "con-vpn-1", "UUID-con-vpn-1-REPLACED-REPLACED-REP"
            )
        )

        self.call_nmcli(
            [
                "connection",
                "add",
                "type",
                "vpn",
                "con-name",
                "con-vpn-1",
                "ifname",
                "*",
                "vpn-type",
                "openvpn",
                "vpn.data",
                "key1 = val1,   key2  = val2, key3=val3",
            ],
            replace_stdout=replace_uuids,
        )

        self.call_nmcli_l(["con", "s"], replace_stdout=replace_uuids)
        self.call_nmcli_l(["con", "s", "con-vpn-1"], replace_stdout=replace_uuids)

        self.call_nmcli(["con", "up", "con-xx1"])
        self.call_nmcli_l(["con", "s"], replace_stdout=replace_uuids)

        self.call_nmcli(["con", "up", "con-vpn-1"])
        self.call_nmcli_l(["con", "s"], replace_stdout=replace_uuids)
        self.call_nmcli_l(["con", "s", "con-vpn-1"], replace_stdout=replace_uuids)

        self.ctx.async_wait()

        self.ctx.srv.setProperty(
            "/org/freedesktop/NetworkManager/ActiveConnection/2",
            "VpnState",
            dbus.UInt32(NM.VpnConnectionState.ACTIVATED),
        )

        uuids = Util.replace_text_sort_list(
            [c[1] for c in self.ctx.srv.findConnections()], replace_uuids
        )

        self.call_nmcli_l([], replace_stdout=replace_uuids)

        for mode in Util.iter_nmcli_output_modes():

            self.call_nmcli_l(
                mode + ["con", "s", "con-vpn-1"], replace_stdout=replace_uuids
            )
            self.call_nmcli_l(
                mode + ["con", "s", "con-vpn-1"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(
                mode + ["-f", "ALL", "con", "s", "con-vpn-1"],
                replace_stdout=replace_uuids,
            )

            # This only filters 'vpn' settings from the connection profile.
            # Contrary to '-f GENERAL' below, it does not show the properties of
            # the activated VPN connection. This is a nmcli bug.
            self.call_nmcli_l(
                mode + ["-f", "VPN", "con", "s", "con-vpn-1"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                mode + ["-f", "GENERAL", "con", "s", "con-vpn-1"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(mode + ["dev", "s"], replace_stdout=replace_uuids)

            self.call_nmcli_l(
                mode + ["-f", "all", "dev", "status"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(mode + ["dev", "show"], replace_stdout=replace_uuids)

            self.call_nmcli_l(
                mode + ["-f", "all", "dev", "show"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(
                mode + ["dev", "show", "wlan0"], replace_stdout=replace_uuids
            )

            self.call_nmcli_l(
                mode + ["-f", "all", "dev", "show", "wlan0"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                mode
                + [
                    "-f",
                    "GENERAL,GENERAL.HWADDR,WIFI-PROPERTIES",
                    "dev",
                    "show",
                    "wlan0",
                ],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                mode
                + [
                    "-f",
                    "GENERAL,GENERAL.HWADDR,WIFI-PROPERTIES",
                    "dev",
                    "show",
                    "wlan0",
                ],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                mode + ["-f", "DEVICE,TYPE,DBUS-PATH", "dev"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                mode + ["-f", "ALL", "device", "wifi", "list"],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode + ["-f", "COMMON", "device", "wifi", "list"],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode
                + [
                    "-f",
                    "NAME,SSID,SSID-HEX,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY,WPA-FLAGS,RSN-FLAGS,DEVICE,ACTIVE,IN-USE,DBUS-PATH",
                    "device",
                    "wifi",
                    "list",
                ],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode
                + ["-f", "ALL", "device", "wifi", "list", "bssid", "C0:E2:BE:E8:EF:B6"],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode
                + [
                    "-f",
                    "COMMON",
                    "device",
                    "wifi",
                    "list",
                    "bssid",
                    "C0:E2:BE:E8:EF:B6",
                ],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode
                + [
                    "-f",
                    "NAME,SSID,SSID-HEX,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY,WPA-FLAGS,RSN-FLAGS,DEVICE,ACTIVE,IN-USE,DBUS-PATH",
                    "device",
                    "wifi",
                    "list",
                    "bssid",
                    "C0:E2:BE:E8:EF:B6",
                ],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode + ["-f", "ALL", "device", "show", "wlan0"],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode + ["-f", "COMMON", "device", "show", "wlan0"],
                replace_stdout=replace_uuids,
            )
            self.call_nmcli_l(
                mode
                + [
                    "-f",
                    "GENERAL,CAPABILITIES,WIFI-PROPERTIES,AP,WIRED-PROPERTIES,WIMAX-PROPERTIES,NSP,IP4,DHCP4,IP6,DHCP6,BOND,TEAM,BRIDGE,VLAN,BLUETOOTH,CONNECTIONS",
                    "device",
                    "show",
                    "wlan0",
                ],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                mode + ["dev", "lldp", "list", "ifname", "eth0"],
                replace_stdout=replace_uuids,
            )

            self.call_nmcli_l(
                mode
                + [
                    "-f",
                    "connection.id,connection.uuid,connection.type,connection.interface-name,802-3-ethernet.mac-address,vpn.user-name",
                    "connection",
                    "show",
                ]
                + uuids,
                replace_stdout=replace_uuids,
                replace_cmd=replace_uuids,
            )

    @nm_test_no_dbus
    def test_offline(self):

        # Make sure we're not using D-Bus
        no_dbus_env = {
            "DBUS_SYSTEM_BUS_ADDRESS": "very:invalid",
            "DBUS_SESSION_BUS_ADDRESS": "very:invalid",
        }

        # This check just makes sure the above works and the
        # "nmcli g" command indeed fails talking to D-Bus
        self.call_nmcli(
            ["g"],
            extra_env=no_dbus_env,
            replace_stderr=[
                Util.ReplaceTextRegex(
                    # depending on glib version, it prints `%s', '%s', or “%s”.
                    # depending on libc version, it converts unicode to ? or *.
                    r"Key/Value pair 0, [`*?']invalid[*?'], in address element [`*?']very:invalid[*?'] does not contain an equal sign",
                    "Key/Value pair 0, 'invalid', in address element 'very:invalid' does not contain an equal sign",
                )
            ],
        )

        replace_uuids = [
            Util.ReplaceTextRegex(
                r"\buuid=[-a-f0-9]+\b", "uuid=UUID-WAS-HERE-BUT-IS-NO-MORE-SADLY"
            )
        ]

        self.call_nmcli(
            ["--offline", "c", "add", "type", "ethernet"],
            extra_env=no_dbus_env,
            replace_stdout=replace_uuids,
        )

        self.call_nmcli(
            ["--offline", "c", "show"],
            extra_env=no_dbus_env,
        )

        self.call_nmcli(
            ["--offline", "g"],
            extra_env=no_dbus_env,
        )

        self.call_nmcli(
            ["--offline"],
            extra_env=no_dbus_env,
        )

        self.call_nmcli(
            [
                "--offline",
                "c",
                "add",
                "type",
                "wifi",
                "ssid",
                "lala",
                "802-1x.eap",
                "pwd",
                "802-1x.identity",
                "foo",
                "802-1x.password",
                "bar",
            ],
            extra_env=no_dbus_env,
            replace_stdout=replace_uuids,
        )

        self.call_nmcli(
            [
                "--offline",
                "c",
                "add",
                "type",
                "wifi",
                "ssid",
                "lala",
                "802-1x.eap",
                "pwd",
                "802-1x.identity",
                "foo",
                "802-1x.password",
                "bar",
                "802-1x.password-flags",
                "agent-owned",
            ],
            extra_env=no_dbus_env,
            replace_stdout=replace_uuids,
        )

        self.call_nmcli(
            ["--complete-args", "--offline", "conn", "modify", "ipv6.ad"],
            extra_env=no_dbus_env,
        )

    @Util.skip_without_pexpect
    @nm_test
    def test_ask_mode(self):
        nmc = Util.cmd_call_pexpect_nmcli(["--ask", "c", "add"])
        nmc.pexp.expect("Connection type:")
        nmc.pexp.sendline("ethernet")
        nmc.pexp.expect("Interface name:")
        nmc.pexp.sendline("eth0")
        nmc.pexp.expect("There are 3 optional settings for Wired Ethernet.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect("There are 2 optional settings for IPv4 protocol.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect("There are 2 optional settings for IPv6 protocol.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect("There are 4 optional settings for Proxy.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect("Connection 'ethernet' \(.*\) successfully added.")
        nmc.pexp.expect(pexpect.EOF)
        Util.valgrind_check_log(nmc.valgrind_log, "test_ask_mode")

    @Util.skip_without_pexpect
    @nm_test
    def test_ask_offline(self):
        # Make sure we're not using D-Bus
        no_dbus_env = {
            "DBUS_SYSTEM_BUS_ADDRESS": "very:invalid",
            "DBUS_SESSION_BUS_ADDRESS": "very:invalid",
        }

        nmc = Util.cmd_call_pexpect_nmcli(
            ["--offline", "--ask", "c", "add"], extra_env=no_dbus_env
        )
        nmc.pexp.expect("Connection type:")
        nmc.pexp.sendline("ethernet")
        nmc.pexp.expect("Interface name:")
        nmc.pexp.sendline("eth0")
        nmc.pexp.expect("There are 3 optional settings for Wired Ethernet.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect("There are 2 optional settings for IPv4 protocol.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect("There are 2 optional settings for IPv6 protocol.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect("There are 4 optional settings for Proxy.")
        nmc.pexp.expect("Do you want to provide them\? \(yes/no\) \[yes]")
        nmc.pexp.sendline("no")
        nmc.pexp.expect(
            "\[connection\]\r\n"
            + "id=ethernet\r\n"
            + "uuid=.*\r\n"
            + "type=ethernet\r\n"
            + "interface-name=eth0\r\n"
            + "\r\n"
            + "\[ethernet\]\r\n"
            + "\r\n"
            + "\[ipv4\]\r\n"
            + "method=auto\r\n"
            + "\r\n"
            + "\[ipv6\]\r\n"
            + "addr-gen-mode=default\r\n"
            + "method=auto\r\n"
            + "\r\n"
            + "\[proxy\]\r\n"
        )
        nmc.pexp.expect(pexpect.EOF)
        Util.valgrind_check_log(nmc.valgrind_log, "test_ask_offline")

    @Util.skip_without_pexpect
    @nm_test
    def test_monitor(self):
        def start_mon(self):
            nmc = Util.cmd_call_pexpect_nmcli(["monitor"])
            nmc.pexp.expect("NetworkManager is running")
            return nmc

        def end_mon(self, nmc):
            nmc.pexp.kill(signal.SIGINT)
            nmc.pexp.expect(pexpect.EOF)
            Util.valgrind_check_log(nmc.valgrind_log, "test_monitor")

        nmc = start_mon(self)

        self.ctx.srv.op_AddObj("WiredDevice", iface="eth0")
        nmc.pexp.expect("eth0: device created\r\n")

        self.ctx.srv.addConnection(
            {"connection": {"type": "802-3-ethernet", "id": "con-1"}}
        )
        nmc.pexp.expect("con-1: connection profile created\r\n")

        end_mon(self, nmc)

        nmc = start_mon(self)
        self.ctx.srv_shutdown()
        Util.pexpect_expect_all(
            nmc.pexp,
            "con-1: connection profile removed",
            "eth0: device removed",
        )
        nmc.pexp.expect("NetworkManager is stopped")
        end_mon(self, nmc)

    @nm_test_no_dbus  # we need dbus, but we need to pass arguments to srv_start
    def test_version_warn(self):
        self.ctx.srv_start(srv_version="A.B.C")
        self.call_nmcli_l(
            ["c"],
            replace_stderr=[
                Util.ReplaceTextRegex(
                    r"\(" + Util.get_nmcli_version() + r"\)", "(X.Y.Z)"
                )
            ],
        )


###############################################################################


class TestNmCloudSetup(unittest.TestCase):
    def setUp(self):
        Util.skip_without_dbus_session()
        Util.skip_without_NM()
        self.ctx = NMTestContext(self._testMethodName)

    _mac1 = "cc:00:00:00:00:01"
    _mac2 = "cc:00:00:00:00:02"

    _ip1 = "172.31.26.249"
    _ip2 = "172.31.176.249"

    def cloud_setup_test(func):
        """
        Runs the mock NetworkManager along with a mock cloud metadata service.
        """

        def f(self):
            Util.skip_without_pexpect()

            if tuple(sys.version_info[0:2]) < (3, 2):
                # subprocess.Popen()'s "pass_fd" argument requires at least Python 3.2.
                raise unittest.SkipTest("This test requires at least Python 3.2")

            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind(("localhost", 0))

            # The same value as Python's TCPServer uses.
            # Chosen by summoning the sprit of TCP under influence of
            # hallucinogenic substances.
            s.listen(5)

            def pass_socket():
                os.dup2(s.fileno(), 3)

            service_path = PathConfiguration.test_cloud_meta_mock_path()
            env = os.environ.copy()
            env["LISTEN_FDS"] = "1"
            p = subprocess.Popen(
                [sys.executable, service_path, "--empty"],
                stdin=subprocess.PIPE,
                env=env,
                pass_fds=(3,),
                preexec_fn=pass_socket,
            )

            (hostaddr, port) = s.getsockname()
            self.md_conn = HTTPConnection(hostaddr, port=port)
            self.md_url = "http://%s:%d" % (hostaddr, port)
            s.close()

            error = None

            self.ctx.srv_start()
            try:
                func(self)
            except Exception as e:
                error = e
            self.ctx.run_post()

            self.md_conn.close()
            p.stdin.close()
            p.terminate()
            p.wait()

            if error:
                raise error

        return f

    def _mock_devices(self):
        # Add a device with an active connection that has IPv4 configured
        self.ctx.srv.op_AddObj("WiredDevice", iface="eth0", mac="cc:00:00:00:00:01")
        self.ctx.srv.addAndActivateConnection(
            {
                "connection": {"type": "802-3-ethernet", "id": "con-eth0"},
                "ipv4": {"method": "auto"},
            },
            "/org/freedesktop/NetworkManager/Devices/1",
            delay=0,
        )

        # The second connection has no IPv4
        self.ctx.srv.op_AddObj("WiredDevice", iface="eth1", mac="cc:00:00:00:00:02")
        self.ctx.srv.addAndActivateConnection(
            {"connection": {"type": "802-3-ethernet", "id": "con-eth1"}},
            "/org/freedesktop/NetworkManager/Devices/2",
            "",
            delay=0,
        )

    def _mock_path(self, path, body):
        self.md_conn.request("PUT", path, body=body)
        self.md_conn.getresponse().read()

    @cloud_setup_test
    def test_aliyun(self):
        self._mock_devices()

        _aliyun_meta = "/2016-01-01/meta-data/"
        _aliyun_macs = _aliyun_meta + "network/interfaces/macs/"
        self._mock_path(_aliyun_meta, "ami-id\n")
        self._mock_path(
            _aliyun_macs, TestNmCloudSetup._mac2 + "\n" + TestNmCloudSetup._mac1
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac2 + "/vpc-cidr-block", "172.31.16.0/20"
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac2 + "/private-ipv4s",
            TestNmCloudSetup._ip1,
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac2 + "/primary-ip-address",
            TestNmCloudSetup._ip1,
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac2 + "/netmask", "255.255.255.0"
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac2 + "/gateway", "172.31.26.2"
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac1 + "/vpc-cidr-block", "172.31.166.0/20"
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac1 + "/private-ipv4s",
            TestNmCloudSetup._ip2,
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac1 + "/primary-ip-address",
            TestNmCloudSetup._ip2,
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac1 + "/netmask", "255.255.255.0"
        )
        self._mock_path(
            _aliyun_macs + TestNmCloudSetup._mac1 + "/gateway", "172.31.176.2"
        )

        # Run nm-cloud-setup for the first time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_ALIYUN_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_ALIYUN": "yes",
            },
        )

        nmc.pexp.expect("provider aliyun detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("get-config: start fetching meta data")
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # One of the devices has no IPv4 configuration to be modified
        nmc.pexp.expect("device has no suitable applied connection. Skip")
        # The other one was lacking an address set it up.
        nmc.pexp.expect("some changes were applied for provider aliyun")
        nmc.pexp.expect(pexpect.EOF)

        # Run nm-cloud-setup for the second time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_ALIYUN_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_ALIYUN": "yes",
            },
        )

        nmc.pexp.expect("provider aliyun detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("get-config: starting")
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # No changes this time
        nmc.pexp.expect('device needs no update to applied connection "con-eth0"')
        nmc.pexp.expect("no changes were applied for provider aliyun")
        nmc.pexp.expect(pexpect.EOF)

        Util.valgrind_check_log(nmc.valgrind_log, "test_aliyun")

    @cloud_setup_test
    def test_azure(self):
        self._mock_devices()

        _azure_meta = "/metadata/instance"
        _azure_iface = _azure_meta + "/network/interface/"
        _azure_query = "?format=text&api-version=2017-04-02"
        self._mock_path(_azure_meta + _azure_query, "")
        self._mock_path(_azure_iface + _azure_query, "0\n1\n")
        self._mock_path(
            _azure_iface + "0/macAddress" + _azure_query, TestNmCloudSetup._mac1
        )
        self._mock_path(
            _azure_iface + "1/macAddress" + _azure_query, TestNmCloudSetup._mac2
        )
        self._mock_path(_azure_iface + "0/ipv4/ipAddress/" + _azure_query, "0\n")
        self._mock_path(_azure_iface + "1/ipv4/ipAddress/" + _azure_query, "0\n")
        self._mock_path(
            _azure_iface + "0/ipv4/ipAddress/0/privateIpAddress" + _azure_query,
            TestNmCloudSetup._ip1,
        )
        self._mock_path(
            _azure_iface + "1/ipv4/ipAddress/0/privateIpAddress" + _azure_query,
            TestNmCloudSetup._ip2,
        )
        self._mock_path(
            _azure_iface + "0/ipv4/subnet/0/address/" + _azure_query, "172.31.16.0"
        )
        self._mock_path(
            _azure_iface + "1/ipv4/subnet/0/address/" + _azure_query, "172.31.166.0"
        )
        self._mock_path(_azure_iface + "0/ipv4/subnet/0/prefix/" + _azure_query, "20")
        self._mock_path(_azure_iface + "1/ipv4/subnet/0/prefix/" + _azure_query, "20")

        # Run nm-cloud-setup for the first time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_AZURE_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_AZURE": "yes",
            },
        )

        nmc.pexp.expect("provider azure detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("found azure interfaces: 2")
        nmc.pexp.expect("interface\[0]: found a matching device with hwaddr")
        nmc.pexp.expect(
            "interface\[0]: (received subnet address|received subnet prefix 20)"
        )
        nmc.pexp.expect(
            "interface\[0]: (received subnet address|received subnet prefix 20)"
        )
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # One of the devices has no IPv4 configuration to be modified
        nmc.pexp.expect("device has no suitable applied connection. Skip")
        # The other one was lacking an address set it up.
        nmc.pexp.expect("some changes were applied for provider azure")
        nmc.pexp.expect(pexpect.EOF)

        # Run nm-cloud-setup for the second time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_AZURE_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_AZURE": "yes",
            },
        )

        nmc.pexp.expect("provider azure detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("get-config: starting")
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # No changes this time
        nmc.pexp.expect('device needs no update to applied connection "con-eth0"')
        nmc.pexp.expect("no changes were applied for provider azure")
        nmc.pexp.expect(pexpect.EOF)

        Util.valgrind_check_log(nmc.valgrind_log, "test_azure")

    @cloud_setup_test
    def test_ec2(self):
        self._mock_devices()

        _ec2_macs = "/2018-09-24/meta-data/network/interfaces/macs/"
        self._mock_path("/latest/meta-data/", "ami-id\n")
        self._mock_path(
            _ec2_macs, TestNmCloudSetup._mac2 + "\n" + TestNmCloudSetup._mac1
        )
        self._mock_path(
            _ec2_macs + TestNmCloudSetup._mac2 + "/subnet-ipv4-cidr-block",
            "172.31.16.0/20",
        )
        self._mock_path(
            _ec2_macs + TestNmCloudSetup._mac2 + "/local-ipv4s", TestNmCloudSetup._ip1
        )
        self._mock_path(
            _ec2_macs + TestNmCloudSetup._mac1 + "/subnet-ipv4-cidr-block",
            "172.31.166.0/20",
        )
        self._mock_path(
            _ec2_macs + TestNmCloudSetup._mac1 + "/local-ipv4s", TestNmCloudSetup._ip2
        )

        # Run nm-cloud-setup for the first time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_EC2_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_EC2": "yes",
            },
        )

        nmc.pexp.expect("provider ec2 detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("get-config: starting")
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # One of the devices has no IPv4 configuration to be modified
        nmc.pexp.expect("device has no suitable applied connection. Skip")
        # The other one was lacking an address set it up.
        nmc.pexp.expect("some changes were applied for provider ec2")
        nmc.pexp.expect(pexpect.EOF)

        # Run nm-cloud-setup for the second time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_EC2_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_EC2": "yes",
            },
        )

        nmc.pexp.expect("provider ec2 detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("get-config: starting")
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # No changes this time
        nmc.pexp.expect('device needs no update to applied connection "con-eth0"')
        nmc.pexp.expect("no changes were applied for provider ec2")
        nmc.pexp.expect(pexpect.EOF)

        Util.valgrind_check_log(nmc.valgrind_log, "test_ec2")

    @cloud_setup_test
    def test_gcp(self):
        self._mock_devices()

        gcp_meta = "/computeMetadata/v1/instance/"
        gcp_iface = gcp_meta + "network-interfaces/"
        self._mock_path(gcp_meta + "id", "")
        self._mock_path(gcp_iface, "0\n1\n")
        self._mock_path(gcp_iface + "0/mac", TestNmCloudSetup._mac1)
        self._mock_path(gcp_iface + "1/mac", TestNmCloudSetup._mac2)
        self._mock_path(gcp_iface + "0/forwarded-ips/", "0\n")
        self._mock_path(gcp_iface + "0/forwarded-ips/0", TestNmCloudSetup._ip1)
        self._mock_path(gcp_iface + "1/forwarded-ips/", "0\n")
        self._mock_path(gcp_iface + "1/forwarded-ips/0", TestNmCloudSetup._ip2)

        # Run nm-cloud-setup for the first time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_GCP_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_GCP": "yes",
            },
        )

        nmc.pexp.expect("provider GCP detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("found GCP interfaces: 2")
        nmc.pexp.expect("GCP interface\[0]: found a requested device with hwaddr")
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # One of the devices has no IPv4 configuration to be modified
        nmc.pexp.expect("device has no suitable applied connection. Skip")
        # The other one was lacking an address set it up.
        nmc.pexp.expect("some changes were applied for provider GCP")
        nmc.pexp.expect(pexpect.EOF)

        # Run nm-cloud-setup for the second time
        nmc = Util.cmd_call_pexpect(
            ENV_NM_TEST_CLIENT_CLOUD_SETUP_PATH,
            [],
            {
                "NM_CLOUD_SETUP_GCP_HOST": self.md_url,
                "NM_CLOUD_SETUP_LOG": "trace",
                "NM_CLOUD_SETUP_GCP": "yes",
            },
        )

        nmc.pexp.expect("provider GCP detected")
        nmc.pexp.expect("found interfaces: CC:00:00:00:00:01, CC:00:00:00:00:02")
        nmc.pexp.expect("get-config: starting")
        nmc.pexp.expect("get-config: success")
        nmc.pexp.expect("meta data received")
        # No changes this time
        nmc.pexp.expect('device needs no update to applied connection "con-eth0"')
        nmc.pexp.expect("no changes were applied for provider GCP")
        nmc.pexp.expect(pexpect.EOF)

        Util.valgrind_check_log(nmc.valgrind_log, "test_gcp")


###############################################################################


def main():
    global dbus_session_inited

    if len(sys.argv) >= 2 and sys.argv[1] == "--started-with-dbus-session":
        dbus_session_inited = True
        del sys.argv[1]

    if not dbus_session_inited:
        # we don't have yet our own dbus-session. Reexec ourself with
        # a new dbus-session.
        try:
            try:
                os.execlp(
                    "dbus-run-session",
                    "dbus-run-session",
                    "--",
                    sys.executable,
                    __file__,
                    "--started-with-dbus-session",
                    *sys.argv[1:],
                )
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
                # we have no dbus-run-session in path? Fall-through
                # to skip tests gracefully
            else:
                raise Exception("unknown error during exec")
        except Exception as e:
            assert False, "Failure to re-exec dbus-run-session: %s" % (str(e))

    if not dbus_session_inited:
        # we still don't have a D-Bus session. Probably dbus-run-session is not available.
        # retry with dbus-launch
        if os.system("type dbus-launch 1>/dev/null") == 0:
            try:
                os.execlp(
                    "bash",
                    "bash",
                    "-e",
                    "-c",
                    "eval `dbus-launch --sh-syntax`;\n"
                    + 'trap "kill $DBUS_SESSION_BUS_PID" EXIT;\n'
                    + "\n"
                    + Util.shlex_join(
                        [
                            sys.executable,
                            __file__,
                            "--started-with-dbus-session",
                        ]
                        + sys.argv[1:]
                    )
                    + " \n"
                    + "",
                )
            except Exception as e:
                m = str(e)
            else:
                m = "unknown error"
            assert False, "Failure to re-exec to start script with dbus-launch: %s" % (
                m
            )

    r = unittest.main(exit=False)

    sys.exit(not r.result.wasSuccessful())


if __name__ == "__main__":
    main()
