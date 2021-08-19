libnm-client-public
===================

libnm is NetworkManager's client API. It has a public API.
This API consists of two parts:

- the handling of connections (`NMConnection`), implemented
  by libnm-core-impl.
- the caching of D-Bus API (`NMClient`), implemented by
  libnm-client-impl.

This directory contains public headers that are used by libnm
users. As such, it's the `NMClient` part of libnm-core-public.

These headers are usable to any libnm client application and
to libnm itself. But not to libnm-core-impl or the daemon.
