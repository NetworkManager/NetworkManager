src/
====

Most of the subdirectories are static helper libraries, which
get linked into one of the final build artifacts (like libnm,
nmcli or NetworkManager). Static libraries are internal API.

The only public API is libnm, which is a shared library provided
client implementations.

Our own clients (like nmcli and nmtui) also use libnm, the shared library.
But they also use additional static helper libraries.

The daemon statically links against a part of libnm, the part that provides
connection profiles. That is libnm-core. libnm-core is thus statically linked
with libnm and the daemon. It does not get linked by clients that already link
with libnm (like nmtui).

Read the individual README.md files in the subdirectories for details:

| Directory                                            | Description                                             |
|------------------------------------------------------|---------------------------------------------------------|
| [core/](core/)                                       | the NetworkManager daemon |
| [nmcli/](nmcli/)                                     | nmcli application, a command line client for NetworkManager |
| [nmtui/](nmtui/)                                     | nmtui application, a text UI client for NetworkManager |
| [nm-cloud-setup/](nm-cloud-setup/)                   | service to automatically configure NetworkManager in cloud environment |
| [nm-initrd-generator/](nm-initrd-generator/)         | generates NetworkManager configuration by parsing kernel command line options for dracut/initrd |
| [nm-dispatcher/](nm-dispatcher/)                     | NetworkManager-dispatcher service to run user scripts |
| [nm-online/](nm-online/)                             | application which checks whether NetworkManager is done, for implementing NetworkManager-wait-online.service |
| [nm-sudo/](nm-sudo/)                                 | internal service for privileged operations |
| [nm-daemon-helper/](nm-daemon-helper/)               | internal helper binary spawned by NetworkManager |
|                                                      | |
| [libnm-std-aux/](libnm-std-aux/)                     | internal helper library for standard C |
| [libnm-glib-aux/](libnm-glib-aux/)                   | internal helper library for glib |
| [libnm-log-null/](libnm-log-null/)                   | internal helper library with dummy (null) logging backend |
| [libnm-log-core/](libnm-log-core/)                   | internal helper library with logging backend (syslog) used by daemon |
| [libnm-base/](libnm-base/)                           | internal helper library with base definitions |
| [libnm-platform/](libnm-platform/)                   | internal helper library for netlink and other platform/kernel API |
| [libnm-udev-aux/](libnm-udev-aux/)                   | internal helper library for libudev |
|                                                      | |
| [libnm-core-public/](libnm-core-public/)             | public API of libnm (libnm-core part) |
| [libnm-core-intern/](libnm-core-intern/)             | internal API of libnm-core, used by libnm and daemon |
| [libnm-core-impl/](libnm-core-impl/)                 | implementation of libnm-core |
| [libnm-core-aux-intern/](libnm-core-aux-intern/)     | internal helper library on top of libnm-core (used by libnm-core itself) |
| [libnm-core-aux-extern/](libnm-core-aux-extern/)     | internal helper library on top of libnm-core (not used by libnm-core) |
| [libnm-client-public/](libnm-client-public/)         | public API of libnm (NMClient part) |
| [libnm-client-impl/](libnm-client-impl/)             | implementation of libnm (NMClient) |
| [libnm-client-aux-extern/](libnm-client-aux-extern/) | internal helper library on top of libnm (not used by libnm itself) |
| [libnmc-base/](libnmc-base/)                         | internal helper library for libnm clients |
| [libnmc-setting/](libnmc-setting/)                   | internal helper library for setting connection profiles (used by nmcli) |
| [libnmt-newt/](libnmt-newt/)                         | internal helper library for libnewt for nmtui |
|                                                      | |
| [linux-headers/](linux-headers/)                     | extra Linux kernel UAPI headers |
| [contrib/](contrib/)                                 | sources that are not used by NetworkManager itself |
| [tests/](tests/)                                     | unit tests that are not specific to one of the other directories |
| [libnm-client-test/](libnm-client-test/)             | internal helper library with test utils for libnm |
|                                                      | |
| [c-list/](c-list/)                                   | fork of c-util helper library for intrusive, doubly linked list |
| [c-rbtree/](c-rbtree/)                               | fork of c-util helper library for intrusive Red-Black Tree |
| [c-siphash/](c-siphash/)                             | fork of c-util helper library for SIPHash24 |
| [c-stdaux/](c-stdaux/)                               | fork of c-util general purpose helpers for standard C |
| [n-acd/](n-acd/)                                     | fork of nettools IPv4 ACD library |
| [n-dhcp4/](n-dhcp4/)                                 | fork of nettools DHCPv4 library |
| [libnm-systemd-core/](libnm-systemd-core/)           | fork of systemd code as network library |
| [libnm-systemd-shared/](libnm-systemd-shared/)       | fork of systemd code as general purpose library |
