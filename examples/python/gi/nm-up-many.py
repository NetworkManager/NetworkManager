#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

# A example script to activate many profiles in parallel.
#
# It uses entirely asynchronous API. At various points the
# script explicitly iterates the main context, which is unlike
# a more complex application that uses the GMainContext, which
# probably would run the context only at one point as long as
# the application is running (from the main function).

import gi
import os
import sys
import time

gi.require_version("NM", "1.0")
from gi.repository import NM, GLib


class MyError(Exception):
    pass


NUM_PARALLEL_STARTING = 10
NUM_PARALLEL_IN_PROGRESS = 50

s = os.getenv("NUM_PARALLEL_STARTING")
if s:
    NUM_PARALLEL_STARTING = int(s)

s = os.getenv("NUM_PARALLEL_IN_PROGRESS")
if s:
    NUM_PARALLEL_IN_PROGRESS = int(s)


start_time = time.monotonic()


def log(msg):
    # use nm_utils_print(), so that the log messages are in synch with
    # LIBNM_CLIENT_DEBUG=trace messages.
    NM.utils_print(0, "[%015.10f] %s\n" % (time.monotonic() - start_time, msg))


def nmc_new(io_priority=GLib.PRIORITY_DEFAULT, cancellable=None):
    # create a NMClient instance using the async initialization
    # (but the function itself iterates the main context until
    # the initialization completes).

    result = []

    def cb(source_object, res):

        try:
            source_object.init_finish(res)
        except Exception as e:
            result.append(e)
        else:
            result.append(None)

    nmc = NM.Client()
    nmc.init_async(io_priority, cancellable, cb)
    while not result:
        nmc.get_main_context().iteration(may_block=True)

    if result[0]:
        raise result[0]

    log("initialized NMClient cache")

    return nmc


def nmc_destroy(nmc_transfer_ref):

    # Just for fun, show how to completely cleanup a NMClient instance.
    # An NMClient instance registers D-Bus signals and unrefing the instance
    # will cancel/unsubscribe those signals, but there might still be some
    # pending operations scheduled on the main context. That means, after
    # unrefing the NMClient instance, we may need to iterate the GMainContext
    # a bit longer, go get rid of all resources (otherwise, the GMainContext
    # itself cannot be destroyed and leaks).
    #
    # We can use nm_client_get_context_busy_watcher() for that, by subscribing
    # a weak reference and iterating the context as long as the object is
    # alive.

    nmc = nmc_transfer_ref[0]
    del nmc_transfer_ref[0]

    alive = [1]

    def weak_ref_cb(alive):
        del alive[0]

    nmc.get_context_busy_watcher().weak_ref(weak_ref_cb, alive)
    main_context = nmc.get_main_context()

    del nmc

    while alive:
        main_context.iteration(may_block=True)

    log("NMClient instance cleaned up")


def find_connections(nmc, argv):

    # parse the inpurt argv and select the connection profiles to activate.
    # The arguments are either "connection.id" or "connection.uuid", possibly
    # qualified by "id" or "uuid".

    result = []

    while True:
        if not argv:
            break
        arg_type = argv.pop(0)
        if arg_type in ["id", "uuid"]:
            if not argv:
                raise MyError('missing specifier after "%s"' % (arg_type))
            arg_param = argv.pop(0)
        else:
            arg_param = arg_type
            arg_type = "*"

        cc = []
        for c in nmc.get_connections():
            if arg_type in ["id", "*"] and arg_param == c.get_id():
                cc.append(c)
            if arg_type in ["uuid", "*"] and arg_param == c.get_uuid():
                cc.append(c)

        if not cc:
            raise MyError(
                'Could not find a matching connection "%s" "%s"' % (arg_type, arg_param)
            )
        if len(cc) > 1:
            raise MyError(
                'Could not find a unique matching connection "%s" "%s", instead %d profiles found'
                % (arg_type, arg_param, len(cc))
            )

        if cc[0] not in result:
            # we allow duplicates, but combine them.
            result.extend(cc)

    for c in result:
        log(
            "requested connection: %s (%s) (%s)"
            % (c.get_id(), c.get_uuid(), c.get_path())
        )

    return result


class Activation(object):
    ACTIVATION_STATE_START = "start"
    ACTIVATION_STATE_STARTING = "starting"
    ACTIVATION_STATE_WAITING = "waiting"
    ACTIVATION_STATE_DONE = "done"

    def __init__(self, con):
        self.con = con
        self.state = Activation.ACTIVATION_STATE_START
        self.result_msg = None
        self.result_ac = None
        self.ac_result = None
        self.wait_id = None

    def __str__(self):
        return "%s (%s)" % (self.con.get_id(), self.con.get_uuid())

    def is_done(self, log=log):

        if self.state == Activation.ACTIVATION_STATE_DONE:
            return True

        if self.state != Activation.ACTIVATION_STATE_WAITING:
            return False

        def _log_result(self, msg, done_with_success=False):
            log("connection %s done: %s" % (self, msg))
            self.state = Activation.ACTIVATION_STATE_DONE
            self.done_with_success = done_with_success
            return True

        ac = self.result_ac
        if not ac:
            return _log_result(self, "failed activation call (%s)" % (self.result_msg,))

        if ac.get_client() is None:
            return _log_result(self, "active connection disappeared")

        if ac.get_state() > NM.ActiveConnectionState.ACTIVATED:
            return _log_result(
                self, "connection failed to activate (state %s)" % (ac.get_state())
            )

        if ac.get_state() == NM.ActiveConnectionState.ACTIVATED:
            return _log_result(
                self, "connection successfully activated", done_with_success=True
            )

        return False

    def start(self, nmc, cancellable=None, activated_callback=None, log=log):

        # Call nmc.activate_connection_async() and return a user data
        # with the information about the pending operation.

        assert self.state == Activation.ACTIVATION_STATE_START

        self.state = Activation.ACTIVATION_STATE_STARTING

        log("activation %s start asynchronously" % (self))

        def cb_activate_connection(source_object, res):
            assert self.state == Activation.ACTIVATION_STATE_STARTING
            try:
                ac = nmc.activate_connection_finish(res)
            except Exception as e:
                self.result_msg = str(e)
                log(
                    "activation %s started asynchronously failed: %s"
                    % (self, self.result_msg)
                )
            else:
                self.result_msg = "success"
                self.result_ac = ac
                log(
                    "activation %s started asynchronously success: %s"
                    % (self, ac.get_path())
                )
            self.state = Activation.ACTIVATION_STATE_WAITING
            if activated_callback is not None:
                activated_callback(self)

        nmc.activate_connection_async(
            self.con, None, None, cancellable, cb_activate_connection
        )

    def wait(self, done_callback=None, log=log):

        assert self.state == Activation.ACTIVATION_STATE_WAITING
        assert self.result_ac
        assert self.wait_id is None

        def cb_wait(ac, state):
            if self.is_done(log=log):
                self.result_ac.disconnect(self.wait_id)
                self.wait_id = None
                done_callback(self)

        log("waiting for %s to fully activate" % (self))
        self.wait_id = self.result_ac.connect("notify", cb_wait)


class Manager(object):
    def __init__(self, nmc, cons):

        self.nmc = nmc

        self.ac_start = [Activation(c) for c in cons]
        self.ac_starting = []
        self.ac_waiting = []
        self.ac_done = []

    def _log(self, msg):

        lists = [self.ac_start, self.ac_starting, self.ac_waiting, self.ac_done]

        n = sum(len(l) for l in lists)
        n = str(len(str(n)))

        prefix = "/".join((("%0" + n + "d") % len(l)) for l in lists)
        log("%s: %s" % (prefix, msg))

    def ac_run(self):

        loop = GLib.MainLoop(self.nmc.get_main_context())

        while self.ac_start or self.ac_starting or self.ac_waiting:

            rate_limit_parallel_in_progress = (
                len(self.ac_starting) + len(self.ac_waiting) >= NUM_PARALLEL_IN_PROGRESS
            )

            if (
                not rate_limit_parallel_in_progress
                and self.ac_start
                and len(self.ac_starting) < NUM_PARALLEL_STARTING
            ):
                activation = self.ac_start.pop(0)
                self.ac_starting.append(activation)

                def cb_activated(activation2):
                    self.ac_starting.remove(activation2)
                    if activation2.is_done(log=self._log):
                        self.ac_done.append(activation2)
                    else:
                        self.ac_waiting.append(activation2)

                        def cb_done(activation3):
                            self.ac_waiting.remove(activation3)
                            self.ac_done.append(activation3)
                            loop.quit()

                        activation2.wait(done_callback=cb_done, log=self._log)
                    loop.quit()

                activation.start(
                    self.nmc, activated_callback=cb_activated, log=self._log
                )
                continue

            loop.run()

        res_list = [ac.done_with_success for ac in self.ac_done]

        log(
            "%s out of %s activations are now successfully activated"
            % (sum(res_list), len(self.ac_done))
        )

        return all(res_list)


def main():
    nmc = nmc_new()

    cons = find_connections(nmc, sys.argv[1:])

    all_good = Manager(nmc, cons).ac_run()

    nmc_transfer_ref = [nmc]
    del nmc
    nmc_destroy(nmc_transfer_ref)

    sys.exit(0 if all_good else 1)


if __name__ == "__main__":
    main()
