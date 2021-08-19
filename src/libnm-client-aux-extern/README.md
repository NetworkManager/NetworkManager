libnm-client-aux-extern
=======================

libnm-client-aux-extern is a static library that:

 - uses the public parts of "libnm"
 - that can also be statically linked into other users of libnm.

Basically, it is a static library with utility functions that extends
libnm.

That means:

  - you can use it everywhere where you dynamically link with libnm.

Also, since libnm-client-aux-extern itself only uses public (stable)
API of libnm, you theoretically can copy the sources into your
own source tree.

This makes it very similar in purpose to [../libnmc-base/](../libnmc-base/).
The difference might be that this one is smaller and that you could easier
copy+paste this to a libnm application outside this source tree.
