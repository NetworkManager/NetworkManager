nm-libnm-aux is a static library that:

 - uses the public parts of "libnm"
 - that can also be statically linked into other users of libnm.

Basically, it is a static library with utility functions that extends
libnm.

That means:

  - you can use it everywhere where you dynamically link with libnm.

Also, since nm-libnm-aux itself only uses public (stable)
API of libnm, you theoretically can copy the sources into your
own source tree.
