libnm-core-intern
=================

This contains header files only, which are also part of
the internal API of [`libnm-core-impl`](../libnm-core-impl).

[`libnm-core-impl`](../libnm-core-impl) is a static library that (among others) implements
[`libnm-core-public`](../libnm-core-public) (which is a part of the public API of [`libnm`](../../libnm)).
This library gets statically linked into [`libnm`](../../libnm) and `NetworkManager`.
Hence, those components can also access internal (but not private) API of
[`libnm-core-impl`](../libnm-core-impl), and this API is in [`libnm-core-intern`](../libnm-core-intern).

These headers can thus be included by anybody who statically links with
[`libnm-core-impl`](../libnm-core-impl) (including [`libnm-core-impl`](../libnm-core-impl) itself).

The directory should not be added to the include search path, instead
users should explicitly `#include "libnm-core-intern/nm-core-internal.h"`)

There is no source code here and no static library to link against.
