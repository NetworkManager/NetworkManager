libnm-std-aux
=============

A static helper library with general purpose helpers on top of
standard C (C11).

As this has no additional dependencies, we should have all our C code
use this internal helper library. It contains helpers that should be
available (and used) everywhere where we write C.

Our C is gnu11, that is C11 or newer with some GCC-ism. The requirement
is that it is supported by all complilers we care about (in pratice GCC
and Clang).

Parts of this library are usually already included via the `nm-default*.h`
headers.
