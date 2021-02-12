libnm-core-aux-extern
=====================

libnm-core-aux-extern is a static library that is similar to
[`libnm-core-aux-intern`](../libnm-core-aux-intern).

The only difference is that `libnm-core-aux-extern` is not used by
[`libnm-core-impl`](../libnm-core-impl) itself. So you must not
use it there.

Otherwise, it's the same and has the same usage.
