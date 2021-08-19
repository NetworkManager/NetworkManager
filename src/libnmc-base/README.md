libnmc-base
===========

A helper library on top of libnm for our clients.
The "c" in "libnmc-base" stands for clients.

This has no additional dependencies on top of libnm,
so any client application that uses libnm can statically
link with this helper at will.

As such, this is very similar in purpose to [../libnm-client-aux-extern](../libnm-client-aux-extern),
the difference is only in scope.
