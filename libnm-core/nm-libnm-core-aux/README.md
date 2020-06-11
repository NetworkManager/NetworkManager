nm-libnm-core-aux is a static library that:

 - uses parts of "libnm-core", that are public API of "libnm"
 - can be statically linked into users of libnm-core (like libnm
   and NetworkManager).
 - that can also be statically linked into other users of libnm.

Basically, it is a static library with utility functions that extends
libnm-core (the part that is public API of libnm), but can also be
used without full libnm.

That means:

  - you can use it everywhere where you either statically link
    with libnm-core, or dynamically link with libnm.
  - you cannot use it inside libnm-core itself. This is the difference
    between nm-libnm-core-intern and nm-libnm-core-aux.

Also, since nm-libnm-core-aux itself only uses public (stable)
API of libnm, you theoretically can copy the sources into your
own source tree.
