n-acd
=====

IPv4 Address Conflict Detection

The n-acd project implements the IPv4 Address Conflict Detection standard as
defined in RFC-5227. The state machine is implemented in a shared library and
provides a stable ISO-C11 API. The implementation is linux-only and relies
heavily on the API behavior of recent linux kernel releases.

### Project

 * **Website**: <https://nettools.github.io/n-acd>
 * **Bug Tracker**: <https://github.com/nettools/n-acd/issues>
 * **Mailing-List**: <https://groups.google.com/forum/#!forum/nettools-devel>

### Requirements

The requirements for this project are:

 * `Linux kernel >= 3.19`
 * `libc` (e.g., `glibc >= 2.16`)

At build-time, the following software is required:

 * `meson >= 0.41`
 * `pkg-config >= 0.29`

### Build

The meson build-system is used for this project. Contact upstream
documentation for detailed help. In most situations the following
commands are sufficient to build and install from source:

```sh
mkdir build
cd build
meson setup ..
ninja
meson test
ninja install
```

The following configuration options are available:

 * `ebpf`: This boolean controls whether `ebpf` features are used to improve
           the package filtering performance. If disabled, classic bpf will be
           used. This feature requires a rather recent kernel (>=3.19).
           Default is: true

### Repository:

 - **web**:   <https://github.com/nettools/n-acd>
 - **https**: `https://github.com/nettools/n-acd.git`
 - **ssh**:   `git@github.com:nettools/n-acd.git`

### License:

 - **Apache-2.0** OR **LGPL-2.1-or-later**
 - See AUTHORS file for details.
