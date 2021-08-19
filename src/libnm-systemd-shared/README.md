libnm-systemd-shared
====================

This is a fork of systemd source files that are compiled
as a static library with general purpose helpers.

We mainly need this for [../libnm-systemd-core/](../libnm-systemd-core/),
which contains systemd library with network tools (like DHCPv6).

We should not use systemd directly from our sources, beyond what
we really need to make get libnm-systemd-core working.
