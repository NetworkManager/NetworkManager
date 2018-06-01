#!/usr/bin/env python

from __future__ import print_function

import sys

try:
    import gi
    from gi.repository import GLib

    gi.require_version('NM', '1.0')
    from gi.repository import NM
except Exception as e:
    GLib = None
    NM = None

import os
import errno
import unittest
import socket
import itertools
import subprocess
import shlex
import re
import dbus
import time
import dbus.service
import dbus.mainloop.glib

# The test can be configured via the following environment variables:
ENV_NM_TEST_CLIENT_BUILDDIR   = 'NM_TEST_CLIENT_BUILDDIR'
ENV_NM_TEST_CLIENT_NMCLI_PATH = 'NM_TEST_CLIENT_NMCLI_PATH'
ENV_NM_TEST_CLIENT_CHECK_L10N = 'NM_TEST_CLIENT_CHECK_L10N'
ENV_NM_TEST_REGENERATE        = 'NM_TEST_REGENERATE'

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
        return os.path.abspath(PathConfiguration.srcdir() + "/../..")

    @staticmethod
    def test_networkmanager_service_path():
        v = os.path.abspath(PathConfiguration.top_srcdir() + "/tools/test-networkmanager-service.py")
        assert os.path.exists(v), ("Cannot find test server at \"%s\"" % (v))
        return v

###############################################################################

os.sys.path.append(os.path.abspath(PathConfiguration.top_srcdir() + '/examples/python'))
import nmex

dbus_session_inited = False

_DEFAULT_ARG = object()

###############################################################################

class Util:

    @staticmethod
    def python_has_version(major, minor = 0):
        return    sys.version_info[0] > major \
               or (    sys.version_info[0] == major \
                   and sys.version_info[1] >= minor)

    @staticmethod
    def is_string(s):
        if Util.python_has_version(3):
            t = str
        else:
            t = basestring
        return isinstance(s, t)

    _find_unsafe = re.compile(r'[^\w@%+=:,./-]',
                              re.ASCII if sys.version_info[0] >= 3 else 0).search

    @staticmethod
    def quote(s):
        if Util.python_has_version(3, 3):
            return shlex.quote(s)
        if not s:
            return "''"
        if Util._find_unsafe(s) is None:
            return s
        return "'" + s.replace("'", "'\"'\"'") + "'"

    @staticmethod
    def popen_wait(p, timeout = None):
        # wait() has a timeout argument only since 3.3
        if Util.python_has_version(3, 3):
            return p.wait(timeout)
        if timeout is None:
            return p.wait()
        start = nmex.nm_boot_time_ns()
        while True:
            if p.poll() is not None:
                return p.returncode
            if start + (timeout * 1000000000) < nmex.nm_boot_time_ns():
                raise Exception("timeout expired")
            time.sleep(0.05)

    @staticmethod
    def iter_single(itr, min_num = 1, max_num = 1):
        itr = list(itr)
        n = 0
        v = None
        for c in itr:
            n += 1
            if n > 1:
                break
            v = c
        if n < min_num:
            raise AssertionError("Expected at least %s elements, but %s found" % (min_num, n))
        if n > max_num:
            raise AssertionError("Expected at most %s elements, but %s found" % (max_num, n))
        return v

    @staticmethod
    def file_read(filename):
        try:
            with open(filename, 'rb') as f:
                return f.read()
        except:
            return None

    @staticmethod
    def replace_text(text, replace_arr):
        if not replace_arr:
            return text
        text = [text]
        for replace in replace_arr:
            try:
                v_search = replace[0]()
            except TypeError:
                v_search = replace[0]
            assert v_search is None or Util.is_string(v_search)
            if not v_search:
                continue
            v_replace = replace[1]
            v_search = v_search.encode('utf-8')
            v_replace = v_replace.encode('utf-8')
            text2 = []
            for t in text:
                if isinstance(t, tuple):
                    text2.append(t)
                    continue
                t2 = t.split(v_search)
                text2.append(t2[0])
                for t3 in t2[1:]:
                    text2.append( (v_replace,) )
                    text2.append(t3)
            text = text2
        return b''.join([(t[0] if isinstance(t, tuple) else t) for t in text])

###############################################################################

class Configuration:

    def __init__(self):
        self._values = {}

    def get(self, name):
        v = self._values.get(name, None)
        if name in self._values:
            return v
        if name == ENV_NM_TEST_CLIENT_BUILDDIR:
            v = os.environ.get(ENV_NM_TEST_CLIENT_BUILDDIR, PathConfiguration.top_srcdir())
            if not os.path.isdir(v):
                raise Exception("Missing builddir. Set NM_TEST_CLIENT_BUILDDIR?")
        elif name == ENV_NM_TEST_CLIENT_NMCLI_PATH:
            v = os.environ.get(ENV_NM_TEST_CLIENT_NMCLI_PATH, None)
            if v is None:
                try:
                    v = os.path.abspath(self.get(ENV_NM_TEST_CLIENT_BUILDDIR) + "/clients/cli/nmcli")
                except:
                    pass
            if not os.path.exists(v):
                raise Exception("Missing nmcli binary. Set NM_TEST_CLIENT_NMCLI_PATH?")
        elif name == ENV_NM_TEST_CLIENT_CHECK_L10N:
            # if we test locales other than 'C', the output of nmcli depends on whether
            # nmcli can load the translations. Unfortunately, I cannot find a way to
            # make gettext use the po/*.gmo files from the build-dir.
            #
            # hence, such tests only work, if you also issue `make-install`
            #
            # Only by setting NM_TEST_CLIENT_CHECK_L10N=1, these tests are included
            # as well.
            v = (os.environ.get(ENV_NM_TEST_CLIENT_CHECK_L10N, '0') == '1')
        elif name == ENV_NM_TEST_REGENERATE:
            # in the "regenerate" mode, the tests will rewrite the files on disk against
            # which we assert. That is useful, if there are intentional changes and
            # we want to regenerate the expected output.
            v = (os.environ.get(ENV_NM_TEST_REGENERATE, '0') == '1')
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
            return conn.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
        except:
            return None

    def __init__(self):
        service_path = PathConfiguration.test_networkmanager_service_path()
        self._conn = dbus.SessionBus()
        p = subprocess.Popen([sys.executable, service_path],
                             stdin = subprocess.PIPE)

        start = nmex.nm_boot_time_ns()
        while True:
            if p.poll() is not None:
                p.stdin.close()
                if p.returncode == 77:
                    raise unittest.SkipTest('the stub service %s exited with status 77' % (service_path))
                raise Exception('the stub service %s exited unexpectedly' % (service_path))
            nmobj = self._conn_get_main_object(self._conn)
            if nmobj is not None:
                break
            if (nmex.nm_boot_time_ns() - start) / 1000000 >= 2000:
                p.stdin.close()
                p.kill()
                Util.popen_wait(p, 1000)
                raise Exception("after starting stub service the D-Bus name was not claimed in time")

        self._nmobj = nmobj
        self._nmiface = dbus.Interface(nmobj, "org.freedesktop.NetworkManager.LibnmGlibTest")
        self._p = p

    def shutdown(self):
        self._nmobj = None
        self._nmiface = None
        self._conn = None
        self._p.stdin.close()
        self._p.kill()
        Util.popen_wait(self._p, 1000)
        self._p = None
        if self._conn_get_main_object(self._conn) is not None:
            raise Exception("Stub service is not still here although it should shut down")

    class _MethodProxy:
        def __init__(self, parent, method_name):
            self._parent = parent
            self._method_name = method_name
        def __call__(self, *args, **kwargs):
            dbus_iface = kwargs.pop('dbus_iface', None)
            if dbus_iface is None:
                dbus_iface = self._parent._nmiface
            method = dbus_iface.get_dbus_method(self._method_name)
            if kwargs:
                # for convenience, we allow the caller to specify arguments
                # as kwargs. In this case, we construct a a{sv} array as last argument.
                kwargs2 = {}
                args = list(args)
                args.append(kwargs2)
                for k in kwargs.keys():
                    kwargs2[k] = kwargs[k]
            return method(*args)

    def __getattr__(self, member):
        if not member.startswith("op_"):
            raise AttributeError(member)
        return self._MethodProxy(self, member[3:])

    def addConnection(self, connection, verify_connection = True):
        return self.op_AddConnection(connection, verify_connection)

    def findConnectionUuid(self, con_id):
        try:
            u = Util.iter_single(self.op_FindConnections(con_id = con_id))[1]
            assert u, ("Invalid uuid %s" % (u))
        except Exception as e:
            raise AssertionError("Unexpectedly not found connection %s: %s" % (con_id, str(e)))
        return u

    def setProperty(self, path, propname, value, iface_name = None):
        if iface_name is None:
            iface_name = ''
        self.op_SetProperties([
            (path, [
                (iface_name, [
                    (propname, value),
                ]),
            ]),
        ])

###############################################################################

class AsyncProcess():

    def __init__(self,
                 args,
                 env,
                 complete_cb):
        self._args = args
        self._env = env
        self._complete_cb = complete_cb

    def start(self):
        if not hasattr(self, '_p'):
            self._p = subprocess.Popen(self._args,
                                       stdout = subprocess.PIPE,
                                       stderr = subprocess.PIPE,
                                       env = self._env)

    def wait(self):

        self.start()

        Util.popen_wait(self._p, 2000)

        (returncode, stdout, stderr) = (self._p.returncode, self._p.stdout.read(), self._p.stderr.read())

        self._p.stdout.close()
        self._p.stderr.close()
        self._p = None

        self._complete_cb(self, returncode, stdout, stderr)

###############################################################################

file_list = []

class NmTestBase(unittest.TestCase):
    pass

class TestNmcli(NmTestBase):

    def call_nmcli_l(self,
                     args,
                     check_on_disk = _DEFAULT_ARG,
                     expected_returncode = _DEFAULT_ARG,
                     expected_stdout = _DEFAULT_ARG,
                     expected_stderr = _DEFAULT_ARG,
                     replace_stdout = None,
                     replace_stderr = None,
                     sort_lines_stdout = False,
                     extra_env = None,
                     sync_barrier = False):
        frame = sys._getframe(1)
        for lang in [ 'C', 'pl' ]:
            self._call_nmcli(args,
                             lang,
                             check_on_disk,
                             expected_returncode,
                             expected_stdout,
                             expected_stderr,
                             replace_stdout,
                             replace_stderr,
                             sort_lines_stdout,
                             extra_env,
                             sync_barrier,
                             frame)


    def call_nmcli(self,
                   args,
                   langs = None,
                   lang = None,
                   check_on_disk = _DEFAULT_ARG,
                   expected_returncode = _DEFAULT_ARG,
                   expected_stdout = _DEFAULT_ARG,
                   expected_stderr = _DEFAULT_ARG,
                   replace_stdout = None,
                   replace_stderr = None,
                   sort_lines_stdout = False,
                   extra_env = None,
                   sync_barrier = None):

        frame = sys._getframe(1)

        if langs is not None:
            assert lang is None
        else:
            if lang is None:
                lang = 'C'
            langs = [lang]

        if sync_barrier is None:
            sync_barrier = (len(langs) == 1)

        for lang in langs:
            self._call_nmcli(args,
                             lang,
                             check_on_disk,
                             expected_returncode,
                             expected_stdout,
                             expected_stderr,
                             replace_stdout,
                             replace_stderr,
                             sort_lines_stdout,
                             extra_env,
                             sync_barrier,
                             frame)

    def _call_nmcli(self,
                    args,
                    lang,
                    check_on_disk,
                    expected_returncode,
                    expected_stdout,
                    expected_stderr,
                    replace_stdout,
                    replace_stderr,
                    sort_lines_stdout,
                    extra_env,
                    sync_barrier,
                    frame):

        if sync_barrier:
            self.async_wait()

        calling_fcn = frame.f_code.co_name
        calling_num = self._calling_num.get(calling_fcn, 0) + 1
        self._calling_num[calling_fcn] = calling_num

        test_name = '%s-%03d' % (calling_fcn, calling_num)

        # we cannot use frame.f_code.co_filename directly, because it might be different depending
        # on where the file lies and which is CWD. We still want to give the location of
        # the file, so that the user can easier find the source (when looking at the .expected files)
        script_filename = 'clients/tests/test-client.py'
        self.assertTrue(os.path.abspath(frame.f_code.co_filename).endswith(script_filename))

        calling_location = '%s:%d:%s()/%d' % (script_filename, frame.f_lineno, frame.f_code.co_name, calling_num)

        if lang is None or lang == 'C':
            lang = 'C'
            language = ''
        elif lang is 'de':
            lang = 'de_DE.utf8'
            language = 'de'
        elif lang is 'pl':
            lang = 'pl_PL.UTF-8'
            language = 'pl'
        else:
            self.fail('invalid language %s' % (lang))

        env = {}
        if extra_env is not None:
            for k, v in extra_env.items():
                env[k] = v
        for k in ['LD_LIBRARY_PATH',
                  'DBUS_SESSION_BUS_ADDRESS']:
            val = os.environ.get(k, None)
            if val is not None:
                env[k] = val
        env['LANG'] = lang
        env['LANGUAGE'] = language
        env['LIBNM_USE_SESSION_BUS'] = '1'
        env['LIBNM_USE_NO_UDEV'] = '1'
        env['TERM'] = 'linux'

        args = [conf.get(ENV_NM_TEST_CLIENT_NMCLI_PATH)] + list(args)

        if replace_stdout is not None:
            replace_stdout = list(replace_stdout)
        if replace_stderr is not None:
            replace_stderr = list(replace_stderr)

        if check_on_disk is _DEFAULT_ARG:
            check_on_disk = (    expected_returncode is _DEFAULT_ARG
                             and expected_stdout is _DEFAULT_ARG
                             and expected_stderr is _DEFAULT_ARG)
        if expected_returncode is _DEFAULT_ARG:
            expected_returncode = None
        if expected_stdout is _DEFAULT_ARG:
            expected_stdout = None
        if expected_stderr is _DEFAULT_ARG:
            expected_stderr = None

        def complete_cb(async_job,
                        returncode,
                        stdout,
                        stderr):

            stdout = Util.replace_text(stdout, replace_stdout)
            stderr = Util.replace_text(stderr, replace_stderr)

            if sort_lines_stdout:
                stdout = b'\n'.join(sorted(stdout.split(b'\n')))

            ignore_l10n_diff = (    lang != 'C'
                                and not conf.get(ENV_NM_TEST_CLIENT_CHECK_L10N))

            if expected_stderr is not None:
                if expected_stderr != stderr:
                    if ignore_l10n_diff:
                        self._skip_test_for_l10n_diff.append(test_name)
                    else:
                        self.assertEqual(expected_stderr, stderr)
            if expected_stdout is not None:
                if expected_stdout != stdout:
                    if ignore_l10n_diff:
                        self._skip_test_for_l10n_diff.append(test_name)
                    else:
                        self.assertEqual(expected_stdout, stdout)
            if expected_returncode is not None:
                self.assertEqual(expected_returncode, returncode)

            dirname = PathConfiguration.srcdir() + '/test-client.check-on-disk'
            basename = test_name + '.expected'
            filename = os.path.abspath(dirname + '/' + basename)

            if not check_on_disk:
                if os.path.exists(filename):
                    self.fail("The file '%s' exists, although we expect it not to." % (filename))
                return

            file_list.append(basename)

            content_old = Util.file_read(filename)

            content_new = ('location: %s\n' % (calling_location)).encode('utf8') + \
                          ('cmd: $NMCLI %s\n' % (' '.join([Util.quote(a) for a in args[1:]]))).encode('utf8') + \
                          ('lang: %s\n' % (lang)).encode('utf8') + \
                          ('returncode: %d\n' % (returncode)).encode('utf8') + \
                          ('stdout: %d bytes\n>>>\n' % (len(stdout))).encode('utf8') + \
                          stdout + \
                          ('\n<<<\nstderr: %d bytes\n>>>\n' % (len(stderr))).encode('utf8') + \
                          stderr + \
                          '\n<<<\n'.encode('utf8')

            w = conf.get(ENV_NM_TEST_REGENERATE)

            if content_old is not None:
                if content_old == content_new:
                    return

                if not w:
                    if ignore_l10n_diff:
                        self._skip_test_for_l10n_diff.append(test_name)
                        return
                    print("\n\n\nThe file '%s' does not have the expected content:" % (filename))
                    print("ACTUAL OUTPUT:\n[[%s]]\n" % (content_new))
                    print("EXPECT OUTPUT:\n[[%s]]\n" % (content_old))
                    print("Let the test write the file by rerunning with NM_TEST_REGENERATE=1\n\n")
                    raise AssertionError("Unexpected output of command, expected %s. Rerun test with NM_TEST_REGENERATE=1 to regenerate files" % (filename))
            else:
                if not w:
                    self.fail("The file '%s' does not exist. Let the test write the file by rerunning with NM_TEST_REGENERATE=1" % (filename))

            try:
                if not os.path.exists(dirname):
                    os.makedirs(dirname)
                with open(filename, 'wb') as content_file:
                    content_file.write(content_new)
            except Exception as e:
                self.fail("Failure to write '%s': %s" % (filename, e))

        async_job = AsyncProcess(args = args,
                                 env = env,
                                 complete_cb = complete_cb)

        self._async_jobs.append(async_job)

        if sync_barrier:
            self.async_wait()
        else:
            self.async_start()

    def async_start(self):
        # limit number parallel running jobs
        for async_job in self._async_jobs[0:10]:
            async_job.start()

    def async_wait(self):
        while self._async_jobs:
            self.async_start()
            self._async_jobs.pop(0).wait()

    def setUp(self):
        if not dbus_session_inited:
            self.skipTest("Own D-Bus session for testing is not initialized. Do you have dbus-run-session available?")
        if NM is None:
            self.skipTest("gi.NM is not available. Did you build with introspection?")
        self.srv = NMStubServer()
        self._calling_num = {}
        self._skip_test_for_l10n_diff = []
        self._async_jobs = []

    def tearDown(self):
        self.async_wait()
        self.srv.shutdown()
        self.srv = None
        self._calling_num = None
        if self._skip_test_for_l10n_diff:
            # nmcli loads translations from the installation path. This failure commonly
            # happens because you did not install the binary in the --prefix, before
            # running the test. Hence, translations are not available or differ.
            msg = "Skipped asserting for localized tests %s. Set NM_TEST_CLIENT_CHECK_L10N=1 to force fail." % (','.join(self._skip_test_for_l10n_diff))
            if Util.python_has_version(3):
                # python2 does not suppot skipping the test during tearDown()
                self.skipTest(msg)
            print(msg + "\n")
        self._skip_test_for_l10n_diff = None

    def init_001(self):
        self.srv.op_AddObj('WiredDevice',
                           iface = 'eth0')
        self.srv.op_AddObj('WiredDevice',
                           iface = 'eth1')
        self.srv.op_AddObj('WifiDevice',
                           iface = 'wlan0')
        self.srv.op_AddObj('WifiDevice',
                           iface = 'wlan1')

        # add another device with an identical ifname. The D-Bus API itself
        # does not enforce the ifnames are unique.
        self.srv.op_AddObj('WifiDevice',
                           ident = 'wlan1/x',
                           iface = 'wlan1')

        self.srv.op_AddObj('WifiAp',
                           device = 'wlan0')
        self.srv.op_AddObj('WifiAp',
                           device = 'wlan0')
        self.srv.op_AddObj('WifiAp',
                           device = 'wlan0')

        self.srv.op_AddObj('WifiAp',
                           device = 'wlan1')

        self.srv.addConnection( {
                                    'connection': {
                                        'type': '802-3-ethernet',
                                        'id':   'con-1',
                                    },
                                })

    def test_001(self):

        self.call_nmcli_l([])

        self.call_nmcli_l(['-f', 'AP', '-mode', 'multiline', '-p', 'd', 'show', 'wlan0'])

        self.call_nmcli_l(['c', 's'])

        self.call_nmcli_l(['bogus', 's'])

        for mode in [[],
                     ['--mode', 'tabular'],
                     ['--mode', 'multiline']]:
            for fmt in [[],
                        ['--pretty'],
                        ['--terse']]:
                self.call_nmcli_l(mode + fmt + ['general', 'permissions'])

    def test_002(self):
        self.init_001()

        self.call_nmcli_l(['d'])

        self.call_nmcli_l(['-f', 'all', 'd'])

        self.call_nmcli_l([])

        self.call_nmcli_l(['-f', 'AP', '-mode', 'multiline',       'd', 'show', 'wlan0'])
        self.call_nmcli_l(['-f', 'AP', '-mode', 'multiline', '-p', 'd', 'show', 'wlan0'])
        self.call_nmcli_l(['-f', 'AP', '-mode', 'multiline', '-t', 'd', 'show', 'wlan0'])
        self.call_nmcli_l(['-f', 'AP', '-mode', 'tabular',         'd', 'show', 'wlan0'])
        self.call_nmcli_l(['-f', 'AP', '-mode', 'tabular',   '-p', 'd', 'show', 'wlan0'])
        self.call_nmcli_l(['-f', 'AP', '-mode', 'tabular',   '-t', 'd', 'show', 'wlan0'])

        self.call_nmcli_l(['-f', 'ALL', 'd', 'wifi'])

        self.call_nmcli_l(['c'])

        self.call_nmcli_l(['c', 's', 'con-1'])

    def test_003(self):
        self.init_001()

        replace_stdout = []

        replace_stdout.append((lambda: self.srv.findConnectionUuid('con-xx1'), 'UUID-con-xx1-REPLACED-REPLACED-REPLA'))

        self.call_nmcli(['c', 'add', 'type', 'ethernet', 'ifname', '*', 'con-name', 'con-xx1'],
                        replace_stdout = replace_stdout)

        self.call_nmcli_l(['c', 's'],
                          replace_stdout = replace_stdout)

        replace_stdout.append((lambda: self.srv.findConnectionUuid('ethernet'), 'UUID-ethernet-REPLACED-REPLACED-REPL'))

        self.call_nmcli(['c', 'add', 'type', 'ethernet', 'ifname', '*'],
                        replace_stdout = replace_stdout)

        self.call_nmcli_l(['c', 's'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'ALL', 'c', 's'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['--complete-args', '-f', 'ALL', 'c', 's', ''],
                          replace_stdout = replace_stdout,
                          sort_lines_stdout = True)

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
        for dev in ['eth0', 'eth1']:
            self.call_nmcli(['con', 'up', 'ethernet', 'ifname', dev])

            self.call_nmcli_l(['con'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['-f', 'ALL', 'con'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['-f', 'ALL', 'con', 's', '-a'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['-f', 'ACTIVE-PATH,DEVICE,UUID', 'con', 's', '-act'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['-f', 'UUID,NAME', 'con', 's', '--active'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['-f', 'ALL', 'con', 's', 'ethernet'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['con', 's', 'ethernet'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['-f', 'ALL', 'dev', 's', 'eth0'],
                              replace_stdout = replace_stdout)

            self.call_nmcli_l(['-f', 'ALL', 'dev', 'show', 'eth0'],
                              replace_stdout = replace_stdout)

        self.async_wait()

        self.srv.setProperty('/org/freedesktop/NetworkManager/ActiveConnection/1',
                             'State',
                             dbus.UInt32(NM.ActiveConnectionState.DEACTIVATING))

        self.call_nmcli_l(['-f', 'ALL', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'UUID,TYPE', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'UUID,TYPE', '--mode', 'multiline', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'UUID,TYPE', '--mode', 'multiline', '--terse', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'UUID,TYPE', '--mode', 'multiline', '--pretty', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'UUID,TYPE', '--mode', 'tabular', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'UUID,TYPE', '--mode', 'tabular', '--terse', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['-f', 'UUID,TYPE', '--mode', 'tabular', '--pretty', 'con'],
                          replace_stdout = replace_stdout)

        self.call_nmcli_l(['con', 's', 'ethernet'],
                          replace_stdout = replace_stdout)

    def test_004(self):
        self.init_001()

        replace_stdout = []

        replace_stdout.append((lambda: self.srv.findConnectionUuid('con-xx1'), 'UUID-con-xx1-REPLACED-REPLACED-REPLA'))

        self.call_nmcli(['c', 'add', 'type', 'wifi', 'ifname', '*', 'ssid', 'foobar', 'con-name', 'con-xx1'],
                        replace_stdout = replace_stdout)

        self.call_nmcli(['connection', 'mod', 'con-xx1', 'ip.gateway', ''])
        self.call_nmcli(['connection', 'mod', 'con-xx1', 'ipv4.gateway', '172.16.0.1'])
        self.call_nmcli(['connection', 'mod', 'con-xx1', 'ipv6.gateway', '::99'])
        self.call_nmcli(['connection', 'mod', 'con-xx1', '802.abc', ''])
        self.call_nmcli(['connection', 'mod', 'con-xx1', '802-11-wireless.band', 'a'])

###############################################################################

def main():
    global dbus_session_inited

    if len(sys.argv) >= 2 and sys.argv[1] == '--started-with-dbus-session':
        dbus_session_inited = True
        del sys.argv[1]

    if not dbus_session_inited:
        # we don't have yet our own dbus-session. Reexec ourself with
        # a new dbus-session.
        try:
            try:
                os.execlp('dbus-run-session', 'dbus-run-session', '--', sys.executable, __file__, '--started-with-dbus-session', *sys.argv[1:])
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise
                # we have no dbus-run-session in path? Fall-through
                # to skip tests gracefully
            else:
                raise Exception('unknown error during exec')
        except Exception as e:
            assert False, ("Failure to re-exec dbus-run-session: %s" % (str(e)))

    if not dbus_session_inited:
        # we still don't have a D-Bus session. Probably dbus-run-session is not available.
        # retry with dbus-launch
        if os.system('type dbus-launch 1>/dev/null') == 0:
            try:
                os.execlp('bash', 'bash', '-e', '-c',
                          'eval `dbus-launch --sh-syntax`;\n' + \
                          'trap "kill $DBUS_SESSION_BUS_PID" EXIT;\n' + \
                          '\n' + \
                          ' '.join([Util.quote(a) for a in [sys.executable, __file__, '--started-with-dbus-session'] + sys.argv[1:]]) + ' \n' + \
                          '')
            except Exception as e:
                m = str(e)
            else:
                m = 'unknown error'
            assert False, ('Failure to re-exec to start script with dbus-launch: %s' % (m))

    r = unittest.main(exit = False)

    if conf.get(ENV_NM_TEST_REGENERATE):
        make_filename = PathConfiguration.srcdir() + '/test-client.check-on-disk/Makefile.am'
        s_new = '# generated with `NM_TEST_REGENERATE=1 make check`\n' + \
                '\n' + \
                'clients_tests_expected_files = \\\n' + \
                ''.join([('\tclients/tests/test-client.check-on-disk/%s \\\n' % f) for f in sorted(file_list)]) + \
                '\t$(NULL)\n'
        s_new = s_new.encode('utf-8')
        if s_new != Util.file_read(make_filename):
            with open(make_filename, 'wb') as f:
                f.write(s_new)

    sys.exit(not r.result.wasSuccessful())

if __name__ == '__main__':
    main()
