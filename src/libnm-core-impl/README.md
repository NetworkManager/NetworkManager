libnm-core-impl
===============

NetworkManager provides a client library [`libnm`](../../libnm).
NetworkManager core does not (dynamically) link against all of libnm.
Instead, it statically links against a part of it.
That part is the static helper library `libnm-core-impl`.

`libnm-core-impl` implements (and provides) the API from
[`libnm-core-public`](../libnm-core-public), which is part of the public
API of [`libnm`](../../libnm). In this form, `libnm-core-impl` is part
of the implementation of [`libnm`](../../libnm). It also implements (and
provides) an internal API [`libnm-core-intern`](../libnm-core-intern) which
can only be used by those who link statically against `libnm-core-impl`.

Only NetworkManager core and [`libnm`](../../libnm) are allowed to statically
link with `libnm-core-impl`. Consequently, only those are allowed to include
[`libnm-core-intern`](../libnm-core-intern).

This directory should not be added to the include search path of other
components as they are only allowed to include [`libnm-core-public`](../libnm-core-public)
and [`libnm-core-intern`](../libnm-core-intern).
