libnm-systemd-core
==================

This is a fork of systemd source files that are compiled
as a static library with network helpers.

We use systemd's DHCPv6 and LLDP library, by forking their code.

We also still use their DHCPv4 library, but that is about to be replaced
by nettools' n-dhcp4.

This approach of code-reuse is very cumbersome, and we should replace
systemd code by a proper library (like nettools).

We should not use systemd directly from our sources, beyond what
we really need.
