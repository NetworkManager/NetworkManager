libnm-platform
==============

A static helper library that provides `NMPlatform` and other utils.
This is NetworkManager's internal netlink library, but also contains
helpers for sysfs, ethtool and other kernel APIs.

`NMPlaform` is also a cache of objects of the netlink API: `NMPCache`
and `NMPObject`. These objects are used throughout NetworkManager
also for generally tracking information about these types. For example,
`NMPlatformIP4Address` (the public part of a certain type of `NMPObject`)
is not only used to track platform addresses from netlink in the cache,
but to track information about IPv4 addresses in general.

This depends on the following helper libraries

  - [../libnm-std-aux/](../libnm-std-aux/)
  - [../libnm-base/](../libnm-base/)
  - [../libnm-glib-aux/](../libnm-glib-aux/)
  - [../libnm-udev-aux/](../libnm-udev-aux/)
  - [../libnm-log-core/](../libnm-log-core/)
  - [../linux-headers/](../linux-headers/)
