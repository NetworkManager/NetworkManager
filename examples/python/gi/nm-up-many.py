#!/usr/bin/env python
# SPDX-License-Identifier: LGPL-2.1-or-later

# A example script to activate many profiles in parallel.
#
# It uses entirely asynchronous API. At various points the
# script explicitly iterates the main context, which is unlike
# a more complex application that uses the GMainContext, which
# probably would run the context only at one point as long as
# the application is running (from the main function).

import sys
import os
import gi
import time

gi.require_version("NM", "1.0")
from gi.repository import NM, GLib, Gio


start_time = time.monotonic()


class MyError(Exception):
    pass


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


def nmc_activate_start(nmc, con):

    # Call nmc.activate_connection_async() and return a user data
    # with the information about the pending operation.

    activation = {
        "con": con,
        "result": None,
        "result_msg": None,
        "result_ac": None,
        "ac_result": None,
    }

    log("activation %s (%s) start asynchronously" % (con.get_id(), con.get_uuid()))

    def cb(source_object, res, activation):
        # The callback does not call other code for signaling the
        # completion. Instead, we remember in "activation" that
        # the callback was completed.
        #
        # Other code will repeatedly go through the "activation_list"
        # and find those that are completed (nmc_activate_find_completed()).
        try:
            ac = nmc.activate_connection_finish(res)
        except Exception as e:
            activation["result"] = False
            activation["result_msg"] = str(e)
        else:
            activation["result"] = True
            activation["result_msg"] = "success"
            activation["result_ac"] = ac

    nmc.activate_connection_async(con, None, None, None, cb, activation)

    return activation


def nmc_activate_find_completed(activation_list):

    # Iterate over list of "activation" data, find the first
    # one that is completed, remove it from the list and return
    # it.

    for idx, activation in enumerate(activation_list):
        if activation["result"] is not None:
            del activation_list[idx]
            return activation

    return None


def nmc_activate_complete(
    nmc, activation_list, completed_list, num_parallel_invocations
):

    # We schedule activations asynchronously and in parallel. However, we
    # still want to rate limit the number of parallel activations. This
    # function does that: if there are more than "num_parallel_invocations" activations
    # in progress, then wait until the excess number of them completed.
    # The completed ones move from "activation_list" over to "completed_list".

    completed = 0
    while True:

        need_to_wait = len(activation_list) > num_parallel_invocations

        # Even if we don't need to wait (that is, the list of pending activations
        # is reasonably short), we still tentatively iterate the GMainContext a bit.
        if not nmc.get_main_context().iteration(may_block=need_to_wait):
            if need_to_wait:
                continue
            # Ok, nothing ready yet.
            break

        # this is not efficient after each iteration(), but it's good enough.
        # The activation list is supposed to be short.
        activation = nmc_activate_find_completed(activation_list)

        if activation is None:
            continue

        con = activation["con"]
        log(
            "activation %s (%s) start complete: %s%s"
            % (
                con.get_id(),
                con.get_uuid(),
                activation["result_msg"],
                (
                    ""
                    if not activation["result"]
                    else (" (%s)" % (activation["result_ac"].get_path()))
                ),
            )
        )
        completed += 1

        completed_list.append(activation)

    if completed > 0:
        log(
            "completed %d activations, %d activations still pending"
            % (completed, len(activation_list))
        )


def nmc_activate_all(nmc, cons):

    # iterate of all connections ("cons") and activate them
    # in parallel. nmc_activate_complete() is used to rate limits
    # how many parallel invocations we allow.

    num_parallel_invocations = 100

    activation_list = []
    completed_list = []
    for c in cons:
        activation = nmc_activate_start(nmc, c)
        activation_list.append(activation)
        nmc_activate_complete(
            nmc, activation_list, completed_list, num_parallel_invocations
        )
    nmc_activate_complete(nmc, activation_list, completed_list, 0)
    assert not activation_list
    assert len(completed_list) == len(cons)

    return completed_list


def nmc_activate_wait_for_pending(nmc, completed_list):

    # go through the list of activations and wait that they
    # all reach a final state. That is, either that they are failed
    # or fully ACTIVATED state.

    log("wait for all active connection to either reach ACTIVATED state or fail...")

    def log_result(activation, message):
        activation["ac_result"] = message
        log(
            "connection %s (%s) activation fully completed: %s"
            % (ac.get_id(), ac.get_uuid(), message)
        )

    while True:

        # again, it's not efficient to check the entire list for completion
        # after each g_main_context_iteration(). But "completed_list" should
        # be reasonably small.

        activation = None
        for idx, activ in enumerate(completed_list):
            if activ["ac_result"] is not None:
                continue
            if activ["result"] is False:
                log_result(activ, "failed to start activation")
                continue
            ac = activ["result_ac"]
            if ac.get_client() is None:
                log_result(activ, "active connection disappeared")
                continue
            if ac.get_state() == NM.ActiveConnectionState.ACTIVATED:
                log_result(activ, "connection successfully activated")
                continue
            if ac.get_state() > NM.ActiveConnectionState.ACTIVATED:
                log_result(
                    activ, "connection failed to activate (state %s)" % (ac.get_state())
                )
                continue
            activation = activ
            break

        if activation is None:
            log("no more activation to wait for")
            break

        nmc.get_main_context().iteration(may_block=True)


def nmc_activate_check_good(nmc, completed_list):

    # go through the list of activations and check that all of them are
    # in a good state.

    n_good = 0
    n_bad = 0

    for activ in completed_list:
        if activ["result"] is False:
            n_bad += 1
            continue
        ac = activ["result_ac"]
        if ac.get_client() is None:
            n_bad += 1
            continue
        if ac.get_state() != NM.ActiveConnectionState.ACTIVATED:
            n_bad += 1
            continue
        n_good += 1

    log(
        "%d out of %d activations are now successfully activated"
        % (n_good, n_good + n_bad)
    )

    return n_bad == 0


def main():
    nmc = nmc_new()

    cons = find_connections(nmc, sys.argv[1:])

    completed_list = nmc_activate_all(nmc, cons)

    nmc_activate_wait_for_pending(nmc, completed_list)

    all_good = nmc_activate_check_good(nmc, completed_list)

    nmc_transfer_ref = [nmc]
    del nmc
    nmc_destroy(nmc_transfer_ref)

    sys.exit(0 if all_good else 1)


if __name__ == "__main__":
    main()
