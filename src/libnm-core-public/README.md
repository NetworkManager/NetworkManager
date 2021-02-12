libnm-core-public
=================

This contains (mostly) header files only, which are also part of
the public API of [`libnm`](../../libnm).

Also, this API is implemented by the static library [`libnm-core-impl`](../libnm-core-impl),
which in turn is statically linked into NetworkManager core and [`libnm`](../../libnm).

These headers can be used by anybody who either:

- links (statically) against [`libnm-core-impl`](../libnm-core-impl).
- links dynamically against [`libnm`](../../libnm).

Note that there is also one source file: `nm-core-enum-types.c`.
This source file really belongs to [`libnm-core-impl`](../libnm-core-impl) but it is here
because it's a generated file and so far I couldn't figure out how
to generate `nm-core-enum-types.h` here while moving `nm-core-enum-types.c`
to [`libnm-core-impl`](../libnm-core-impl).

Aside `nm-core-enum-types.c`, this directory only provides header files.
Users should add this directory (both srcdir and builddir) to the include
search path, because libnm users are used to include these headers unqualified
(like `#include "nm-setting.h`).
