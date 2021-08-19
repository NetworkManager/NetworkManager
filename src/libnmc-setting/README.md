libnmc-setting
==============

A client library on top of libnm (and libnm-base).
Like libnmc-base, this is a helper library that a libnm
client could use.

But its purpose is more specific. It's mainly about providing
a generic API for handling connection properties. As such, it's
only used by nmcli and in practice also specific to nmcli.

Theoretically, the API is supposed to be generic, so we could
imagine another client that uses this beside nmcli.

Like libnm-base, this has a similar purpose and application
as [../libnm-client-aux-extern/](../libnm-client-aux-extern/),
the difference is that it's even more specific.
