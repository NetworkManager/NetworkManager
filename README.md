c-stdaux
========

Auxiliary macros and functions for the C standard library

The c-stdaux project contains support-macros and auxiliary functions around the
functionality of common C standard libraries. This includes helpers for the
ISO-C Standard Library, but also other common specifications like POSIX or
common extended features of wide-spread compilers like gcc and clang.

### Project

 * **Website**: <https://c-util.github.io/c-stdaux>
 * **Bug Tracker**: <https://github.com/c-util/c-stdaux/issues>

### Requirements

The requirements for this project are:

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

No custom configuration options are available.

### Repository:

 - **web**:   <https://github.com/c-util/c-stdaux>
 - **https**: `https://github.com/c-util/c-stdaux.git`
 - **ssh**:   `git@github.com:c-util/c-stdaux.git`

### License:

 - **Apache-2.0** OR **LGPL-2.1-or-later**
 - See AUTHORS file for details.
