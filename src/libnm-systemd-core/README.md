libnm-systemd-core
==================

This is a fork of systemd source files that are compiled
as a static library with network helpers.

We use systemd's DHCPv6 and LLDP library, by forking their code.

We also still use their DHCPv4 library, but that is about to be replaced
by nettools' n-dhcp4 and not used unless you configure the undocumented
`[main].dhcp=systemd` plugin.

This approach of code-reuse is very cumbersome, and we should replace
systemd code by a proper library (like [nettools](https://github.com/nettools/)).

We should not use systemd directly from our sources, beyond what
we really need.


Reimport Upstream Code
----------------------

Read [here](../libnm-systemd-shared/README.md#reimport-upstream-code).
