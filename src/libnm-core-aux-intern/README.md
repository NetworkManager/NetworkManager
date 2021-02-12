libnm-core-aux-intern
=====================

`libnm-core-aux-intern` is a static library that:

 - uses parts of [`libnm-core-impl`](../libnm-core-impl), that are public API
   of [`libnm`](../../libnm) (i.e. [`libnm-core-public`](../libnm-core-public)).
 - that is statically linked into [`libnm-core-impl`](../libnm-core-impl) (and thus
   [`libnm`](../libnm) and NetworkManager core.
 - that can also be statically linked into other users of [`libnm`](../libnm).

Basically, it is a static library with utility functions that extends
[`libnm-core-impl`](../libnm-core-impl) (the part that is public API of libnm),
but it is also used by [`libnm-core-impl`](../libnm-core-impl) itself.

That means:

  - you can use it everywhere where you either statically link
    with [`libnm-core-impl`](../libnm-core-impl), or dynamically link with
    [`libnm`](../../libnm).
  - you can even use it inside of [`libnm-core-impl`](../libnm-core-impl) itself.
    This is the difference between `libnm-core-aux-intern` and
    [`libnm-core-aux-extern`](..libnm-core-aux-extern).

Note that `libnm-core-aux-intern` only uses public API of `libnm`.

This directory should not be added to the include search path. Instead,
users should fully qualify the include like `#include "libnm-core-aux-intern/nm-auth-subject.h"`.
