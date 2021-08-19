libnm-base
==========

A static helper library with network/NetworkManager specific
code.

Contrary to libnm-glib-aux, this does not contain general purpose
helpers, but code that is more specific about NetworkManager.

This is the most low-level dependency of this kind. Most NetworkManager
specific code will directly or indirectly link with this.

As this is a static library, there is no problem with dragging this into your
binary/library, if your application already depends on libnm-glib-aux (and glib).

Dependencies:

  - glib
  - [../libnm-std-aux/](../libnm-std-aux/)
  - [../libnm-glib-aux/](../libnm-glib-aux/)
