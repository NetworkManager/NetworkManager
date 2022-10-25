#!/bin/python

###############################################################################
# An example that creates a NMClient instance for another GMainContext
# and iterates the context while doing an async D-Bus call.
#
# D-Bus is fundamentally async. libnm's NMClient API caches D-Bus objects
# on NetworkManager's D-Bus API. As such, it is "frozen" (with the current
# content of the cache) while not iterating the GMainContext. Only by iterating
# the GMainContext any events are processed and things change.
#
# This means, NMClient heavily uses GMainContext (and GDBusConnection)
# and to operate it, you need to iterate the GMainContext. The synchronous
# API (like NM.Client.new()) is for simple programs but usually not best
# for using NMClient for real applications.
#
# To learn more about GMainContext, read https://developer.gnome.org/SearchProvider/documentation/tutorials/main-contexts.html
# When I say "mainloop" or "event loop", I mean GMainContext. GMainLoop is
# a small wrapper around GMainContext to run the context with a boolean
# flag.
#
# Usually, non trivial applications run the GMainContext (or GMainLoop)
# from the main() function and aside some setup and teardown, everything
# happens as events from the event loop.
# This example instead performs synchronous steps, and at the places where
# we need to get the result of some async operation, we iterate the GMainContext
# until we get the result. This may not be how a complex application works,
# but you might do this on a simpler application (like a script) that iterates
# the mainloop whenever it needs to wait for async operations to complete.
#
# Iterating the mainloop might dispatch any other sources that are ready.
# In this example nobody else is scheduling unrelated timers or events, but
# if that happens, your application needs to cope with that.
# E.g. while iterating the mainloop many times, still don't nest running the
# same main context (unless you really know what you do).

###############################################################################

import sys
import time
import traceback

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM, GLib, Gio


###############################################################################


def log(msg=None, prefix=None, suffix="\n"):
    # We use nm_utils_print(), because that uses the same logging
    # mechanism as if you run with "LIBNM_CLIENT_DEBUG=trace". This
    # ensures that messages are in sync.
    if msg is None:
        NM.utils_print(0, "\n")
        return
    if prefix is None:
        prefix = f"[{time.monotonic():.5f}] "
    NM.utils_print(0, f"{prefix}{msg}{suffix}")


def error_is_cancelled(e):
    # Whether error is due to cancellation.
    if isinstance(e, GLib.GError):
        if e.domain == "g-io-error-quark" and e.code == Gio.IOErrorEnum.CANCELLED:
            return True
    return False


###############################################################################

# A Context manager for running a mainloop. Of course, this does
# not do anything magically. You can run the context/mainloop without
# this context object.
#
# This is just to show how we could iterate the GMainContext while waiting
# for an async reply. Note that many non-trivial applications that use glib
# would instead run the mainloop from the main function, only running it once,
# but for the entire duration of the program.
#
# This example and MainLoopRun instead assume that you iterate the maincontext
# for short durations at a time. In particular in this case, where there is
# a dedicated maincontext only for NMClient.
class MainLoopRun:
    def __init__(self, info, ctx, timeout=None):
        self._info = info
        self._loop = GLib.MainLoop(ctx)
        self.cancellable = Gio.Cancellable()
        self._timeout = timeout
        self.got_timeout = False
        self.result = None
        self.error = None
        log(f"MainLoopRun[{self._info}]: create with timeout {self._timeout}")

    def _timeout_cb(self, _):
        log(f"MainLoopRun[{self._info}]: timeout")
        self.got_timeout = True
        self._detach()
        self.cancellable.cancel()
        return False

    def _cancellable_cb(self):
        log(f"MainLoopRun[{self._info}]: cancelled")

    def _detach(self):
        if self._timeout_source is not None:
            self._timeout_source.destroy()
            self._timeout_source = None
        if self._cancellable_id is not None:
            self.cancellable.disconnect(self._cancellable_id)
            self._cancellable_id = None

    def __enter__(self):
        log(f"MainLoopRun[{self._info}]: enter")
        self._timeout_source = None
        if self._timeout is not None:
            self._timeout_source = GLib.timeout_source_new(int(self._timeout * 1000))
            self._timeout_source.set_callback(self._timeout_cb)
            self._timeout_source.attach(self._loop.get_context())
        self._cancellable_id = self.cancellable.connect(self._cancellable_cb)
        self._loop.get_context().push_thread_default()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            # Exception happened.
            log(f"MainLoopRun[{self._info}]: exit with exception")
        else:
            log(f"MainLoopRun[{self._info}]: exit: start mainloop")

            self._loop.run()

            if self.error is not None:
                log(
                    f"MainLoopRun[{self._info}]: exit: complete with error {self.error}"
                )
            elif self.result is not None:
                log(
                    f"MainLoopRun[{self._info}]: exit: complete with result {self.result}"
                )
            else:
                log(f"MainLoopRun[{self._info}]: exit: complete with success")

        self._detach()
        self._loop.get_context().pop_thread_default()
        return False

    def quit(self):
        log(f"MainLoopRun[{self._info}]: quit mainloop")
        self._detach()
        self._loop.quit()


###############################################################################


def get_bus():
    # Let's get the GDBusConnection singleton by calling Gio.bus_get().
    # Since we do everything async, use Gio.bus_get() instead Gio.bus_get_sync().
    with MainLoopRun("get_bus", None, 1) as r:

        def bus_get_cb(source, result, r):
            try:
                c = Gio.bus_get_finish(result)
            except Exception as e:
                r.error = e
            else:
                r.result = c
            r.quit()

        Gio.bus_get(Gio.BusType.SYSTEM, r.cancellable, bus_get_cb, r)

    return r.result


###############################################################################


def create_nmc(dbus_connection):
    # Show how to create and initialize a NMClient asynchronously.
    #
    # NMClient implements GAsyncInitableIface, it thus can be initialized
    # asynchronously. That has actually an advantage, because the sync
    # initialization (GInitableIface) requires to create an internal GMainContext
    # which has an overhead.
    #
    # Also, split the GObject creation and the init_async() call in two.
    # That allows to pass construct-only parameters, in particular like
    # the instance_flags.

    # Create a separate context for the NMClient. The NMClient is strongly
    # tied to the context used at construct time.
    ctx = GLib.MainContext()
    ctx.push_thread_default()

    log(f"[create_nmc]: use separate context for NMClient: ctx={ctx}")
    try:
        # We create a client asynchronously. There is synchronous
        # NM.Client(), however that requires an internal GMainContext
        # and has thus an overhead. Also, it's obviously blocking.
        #
        # Instead, we initialize it asynchronously, which means
        # we need to iterate the main context. In this case, the
        # context cannot have any other sources dispatched, but
        # if there would be other sources, they might be dispatched
        # while iterating (so this is waiting for the result, but
        # may also dispatch unrelated sources (if any), which you would need
        # to handle).
        #
        # Also, only when using the GObject constructor directly, we can
        # suppress loading the permissions and pass a D-Bus connection.
        nmc = NM.Client(
            instance_flags=NM.ClientInstanceFlags.NO_AUTO_FETCH_PERMISSIONS,
            dbus_connection=dbus_connection,
        )
        log(f"[create_nmc]: new NMClient instance: {nmc}")
    finally:
        # We actually don't need that the ctx is the current thread default
        # later on. NMClient will automatically push it, when necessary.
        ctx.pop_thread_default()

    with MainLoopRun("create_mnc", nmc.get_main_context(), 2) as r:

        def _async_init_cb(nmc, result, r):
            try:
                nmc.init_finish(result)
            except Exception as e:
                log(f"[create_nmc]: init_async() completed with error: {e}")
                r.error = e
            else:
                log(f"[create_nmc]: init_async() completed with success")
            r.quit()

        log(f"[create_nmc]: start init_async()")
        nmc.init_async(GLib.PRIORITY_DEFAULT, r.cancellable, _async_init_cb, r)

    if r.error is None:
        if nmc.get_nm_running():
            log(
                f"[create_nmc]: completed with success (daemon version: {nmc.get_version()}, D-Bus daemon unique name: {nmc.get_dbus_name_owner()})"
            )
        else:
            log(f"[create_nmc]: completed with success (daemon not running)")
        return nmc
    if error_is_cancelled(r.error):
        # Cancelled by us. This happened because we hit the timeout with
        # MainLoopRun.
        log(f"[create_nmc]: failed to initialize within timeout")
        return None
    if not nmc.get_dbus_connection():
        # The NMClient has no D-Bus connection, it usually would try
        # to get one via Gio.bus_get(), but it failed.
        log(f"[create_nmc]: failed to create D-Bus connection: {r.error}")
        return None

    log(f"[create_nmc]: unexpected error creating NMClient ({r.error})")
    # This actually should not happen. There is no other reason why
    # initialization can fail.
    assert False, "NMClient initialization is not supposed to fail"


###############################################################################


def make_call(nmc):

    log("[make_call]: make some async D-Bus call")

    if not nmc:
        log("[make_call]: no NMClient. Skip")
        return

    with MainLoopRun("make_call", nmc.get_main_context(), 1) as r:

        # There are two reasons why async operations are preferable with
        # D-Bus and libnm:
        #
        # - pseudo blocking messes with the ordering of events (see https://smcv.pseudorandom.co.uk/2008/11/nonblocking/).
        # - blocking prevents other things from happening and combining synchronous calls is more limited.
        #
        # So doing async operations is mostly interesting when performing multiple operations in
        # parallel, or when we still want to handle other events while waiting for the reply.
        # The example here does not cover that usage well, because there is only one thing happening.

        def _dbus_call_cb(nmc, result, r):
            try:
                res = nmc.dbus_call_finish(result)
            except Exception as e:
                if error_is_cancelled(e):
                    log(
                        f"[make_call]: dbus_call() completed with cancellation after timeout"
                    )
                else:
                    log(f"[make_call]: dbus_call() completed with error: {e}")

                # I don't understand why, but if you hit this exception (e.g. by setting a low
                # timeout) and pass the exception to the out context, then an additional reference
                # to nmc is leaked, and destroy_nmc() will fail. Workaround
                #
                # r.error = e
                r.error = str(e)
            else:
                log(
                    f"[make_call]: dbus_call() completed with success: {str(res)[:40]}..."
                )
            r.quit()

        log(f"[make_call]: start GetPermissions call")
        nmc.dbus_call(
            NM.DBUS_PATH,
            NM.DBUS_INTERFACE,
            "GetPermissions",
            GLib.Variant.new_tuple(),
            GLib.VariantType("(a{ss})"),
            1000,
            r.cancellable,
            _dbus_call_cb,
            r,
        )

    return r.error is None


###############################################################################


def destroy_nmc(nmc_holder, destroy_mode):
    # The way to shutdown an NMClient is just by unrefing it.
    #
    # At any moment, can an NMClient instance have pending async operations.
    # While unrefing NMClient will cancel them right away, they are only
    # reaped when we iterate the GMainContext some more. That means, if we don't
    # want to leak the GMainContext and the pending operations, we must
    # iterate it some more.
    #
    # To know how much more, there is nmc.get_context_busy_watcher(),
    # We can subscribe a weak reference and keep iterating as long
    # as the watcher is alive.
    #
    # Of course, this only applies if the application wishes to keep running
    # but no longer iterating NMClient's GMainContext. Then you need to ensure
    # that all pending operations in GMainContext are completed (by iterating it).
    #
    # In python, that is a bit tricky, because the caller of destroy_nmc()
    # must give up its reference and pass it here via the @nmc_holder list.
    # You must call destroy_nmc() without having any other reference on
    # nmc.
    #
    # This is just an example. This relies that on this point we only have
    # one reference to NMClient (and it's held by the nmc_holder list).
    # Usually you wouldn't make assumptions about this. Instead, you just
    # assume that you need to keep iterating the GMainContext as long as
    # the context busy watcher is alive, regardless that at this point others
    # might still hold references on the NMClient.

    # Transfer the nmc reference out of the list.
    (nmc,) = nmc_holder
    nmc_holder.clear()

    log(
        f"[destroy_nmc]: destroying NMClient {nmc}: pyref={sys.getrefcount(nmc)}, ref_count={nmc.ref_count}, destroy_mode={destroy_mode}"
    )

    if destroy_mode == 0:
        ctx = nmc.get_main_context()

        finished = []

        def _weak_ref_cb():
            log(f"[destroy_nmc]: context busy watcher is gone")
            finished.clear()
            finished.append(True)

        # We take a weak ref on the context-busy-watcher object and give up
        # our reference on nmc. This must be the last reference, which initiates
        # the shutdown of the NMClient.
        weak_ref = nmc.get_context_busy_watcher().weak_ref(_weak_ref_cb)
        del nmc

        def _timeout_cb(unused):
            if not finished:
                # Somebody else holds a reference to the NMClient and keeps
                # it alive. We cannot properly clean up.
                log(
                    f"[destroy_nmc]: ERROR: timeout waiting for context busy watcher to be gone"
                )
                finished.append(False)
            return False

        timeout_source = GLib.timeout_source_new(1000)
        timeout_source.set_callback(_timeout_cb)
        timeout_source.attach(ctx)

        while not finished:
            log(f"[destroy_nmc]: iterating main context")
            ctx.iteration(True)

        timeout_source.destroy()

        log(f"[destroy_nmc]: done: {finished[0]}")
        if not finished[0]:
            weak_ref.unref()
            raise Exception("Failure to destroy NMClient: something keeps it alive")

    else:

        if destroy_mode == 1:
            ctx = GLib.MainContext.default()
        else:
            # Run the maincontext of the NMClient.
            ctx = nmc.get_main_context()
        with MainLoopRun("destroy_nmc", ctx, 2) as r:

            def _wait_shutdown_cb(source_unused, result, r):
                try:
                    NM.Client.wait_shutdown_finish(result)
                except Exception as e:
                    if error_is_cancelled(e):
                        log(
                            f"[destroy_nmc]: wait_shutdown() completed with cancellation after timeout"
                        )
                    else:
                        log(f"[destroy_nmc]: wait_shutdown() completed with error: {e}")
                else:
                    log(f"[destroy_nmc]: wait_shutdown() completed with success")

                r.quit()

            nmc.wait_shutdown(True, r.cancellable, _wait_shutdown_cb, r)
            del nmc


###############################################################################


def run1():
    try:
        dbus_connection = get_bus()
        log()

        nmc = create_nmc(dbus_connection)
        log()

        make_call(nmc)
        log()

        if not nmc:
            log(f"[destroy_nmc]: nothing to destroy")
        else:
            # To cleanup the NMClient, we need to give up the reference. Move
            # it to a list, and destroy_nmc() will take care of it.
            nmc_holder = [nmc]
            del nmc

            # In the example, there are three modes how the destroy is
            # implemented.
            destroy_nmc(nmc_holder, destroy_mode=1)

        log()
        log("done")
    except Exception as e:
        log()
        log("EXCEPTION:")
        log(f"{e}")
        for tb in traceback.format_exception(None, e, e.__traceback__):
            for l in tb.split("\n"):
                log(f">>> {l}")
        return False
    return True


if __name__ == "__main__":
    if not run1():
        sys.exit(1)
