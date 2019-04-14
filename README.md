c-rbtree
========

Intrusive Red-Black Tree Collection

The c-rbtree project implements an intrusive collection based on red-black
trees in ISO-C11. Its API guarantees the user full control over its
data-structures, and rather limits itself to just the tree-specific rebalancing
and coloring operations. For API documentation, see the c-rbtree.h header file,
as well as the docbook comments for each function.

### Project

 * **Website**: <https://c-util.github.io/c-rbtree>
 * **Bug Tracker**: <https://github.com/c-util/c-rbtree/issues>

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

 - **web**:   <https://github.com/c-util/c-rbtree>
 - **https**: `https://github.com/c-util/c-rbtree.git`
 - **ssh**:   `git@github.com:c-util/c-rbtree.git`

### License:

 - **Apache-2.0** OR **LGPL-2.1-or-later**
 - See AUTHORS file for details.
