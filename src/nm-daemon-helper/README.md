nm-daemon-helper
================

A internal helper application that is spawned by NetworkManager
to perform certain actions.

Currently all it does is doing a reverse DNS lookup, which
cannot be done by NetworkManager because the operation requires
to reconfigure the libc resolver (which is a process-wide operation).

This is not directly useful to the user.
