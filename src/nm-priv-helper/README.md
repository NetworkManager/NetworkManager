nm-priv-helper
==============

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
