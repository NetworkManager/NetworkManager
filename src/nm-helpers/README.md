nm-helpers
==========

This directory contains stand-alone helper programs used by various
components.

nm-daemon-helper
----------------

A internal helper application that is spawned by NetworkManager
to perform certain actions.

Currently all it does is doing a reverse DNS lookup, which
cannot be done by NetworkManager because the operation requires
to reconfigure the libc resolver (which is a process-wide operation).

This is not directly useful to the user.

nm-priv-helper
--------------

This is a D-Bus activatable, exit-on-idle service, which
provides an internal API to NetworkManager daemon.

This has no purpose for the user, it is an implementation detail
of the daemon.

The purpose is that `nm-priv-helper` can execute certain
privileged operations which NetworkManager process is not
allowed to. We want to sandbox NetworkManager as much as
possible, and nm-priv-helper provides a controlled way to
perform some very specific operations.

As such, nm-priv-helper should still be sandboxed too to only
being able to execute the operations that are necessary for
NetworkManager.

nm-priv-helper will reject all D-Bus requests that are not
originating from the current name owner of
"org.freedesktop.NetworkManager".  That is, it is supposed to
only reply to NetworkManager daemon and as such is not useful to
the user directly.
