libnm-client-impl
=================

libnm is NetworkManager's client API.
This API consists of two parts:

- the handling of connections (`NMConnection`), implemented
  by libnm-core-impl.
- the caching of D-Bus API (`NMClient`), implemented by
  libnm-client-impl.

This directory contains the implementation of the second part.
As such, it will be statically linked with libnm-core-impl
to make libnm. Also, it cannot be used by the daemon.
