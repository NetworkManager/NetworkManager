nm-libnm-core-intern is a static library that:

 - uses parts of "libnm-core", that are public API of "libnm"
 - that is statically linked into libnm-core (and thus libnm
   and NetworkManager).
 - that can also be statically linked into other users of libnm.

Basically, it is a static library with utility functions that extends
libnm-core (the part that is public API of libnm), but it is used
by libnm-core.

That means:

  - you can use it everywhere where you either statically link
    with libnm-core, or dynamically link with libnm.
  - you can even use it inside of libnm-core itself.

Also, since nm-libnm-core-intern itself only uses public (stable)
API of libnm, you theoretically can copy the sources into your
own source tree.
