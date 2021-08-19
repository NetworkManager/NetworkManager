libnm-glib-aux
==============

A static helper library with general purpose helpers on top
of glib.

This is similar to libnm-std-aux (on which this library depends).
The difference is that libnm-std-aux only requires standard C (C11),
while this has a dependency on glib.

As this has no additional dependencies, we should have all our glib code
use this internal helper library. It contains helpers that should be
available (and used) in all our C/glib applications/libraries.

Parts of this library are usually already included via the `nm-default*.h`
headers.
