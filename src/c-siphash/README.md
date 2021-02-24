c-siphash
=========

Streaming-capable SipHash Implementation

The c-siphash project is a standalone implementation of SipHash in Standard
ISO-C11. It provides a streaming-capable API to compute data hashes according
to the SipHash algorithm. For API documentation, see the c-siphash.h header
file, as well as the docbook comments for each function.

### Project

 * **Website**: <https://c-util.github.io/c-siphash>
 * **Bug Tracker**: <https://github.com/c-util/c-siphash/issues>

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

 - **web**:   <https://github.com/c-util/c-siphash>
 - **https**: `https://github.com/c-util/c-siphash.git`
 - **ssh**:   `git@github.com:c-util/c-siphash.git`

### License:

 - **Apache-2.0** OR **LGPL-2.1-or-later**
 - See AUTHORS file for details.
