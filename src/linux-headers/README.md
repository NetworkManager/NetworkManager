linux-headers
=============

Contains a copy of Linux UAPI kernel headers.
When we build against an older kernel, we may
still want to unconditionally build against a
certain version of kernel API.

These headers should be taken without modification
from Linux.

Don't include any of these these headers directly, instead
include "libnm-std-aux/nm-linux-compat.h" which drags these
headers in. This ensures that we include at all places our own
patched variant, instead of the system headers.
