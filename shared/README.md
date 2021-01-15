The "shared/" Directory
=======================

For NetworkManager we place helper/utility code under "shared/"
in static libraries. The idea is to avoid code duplication but also
provide high quality helper functions that simplify the higher layers.
In NetworkManager there are complicated parts, for example "src/nm-manager.c"
is huge. On the other hand, this helper code should be simple and easy
to understand, so that we can build more complex code on top of it.

As we statically link them into our binaries, they are all inherently
internal API, that means they cannot be part of libnm's (libnm-core's) public API.
It also means that their API/ABI is not stable.

We don't care these libraries to be minimal and contain only symbols that are
used by all users. Instead, we expect the linker to throw away unused symbols.
We achieve this by having a symbol versioning file to hide internal symbols
(which gives the linker a possibility to remove them if they are unused) and
compiling with LTO or `"-Wl,--gc-sections"`. Let the tool solve this and not
manual organization.

Hence these libraries (and their content) are structured this way to satisfy
the following questions:

1) which dependencies (libraries) do they have? That determines which
   other libraries can use it. For example:

   - "shared/nm-std-aux" and "shared/nm-glib-aux" both provide general
     purpose helpers, the difference is that the former has no dependency
     on glib2 library. Both these libraries are a basic dependency for
     many other parts of the code.

   - "shared/nm-udev-aux" has a dependency on libudev, it thus cannot
     be in "shared/nm-glib-aux".

   - client code also has a glib2 dependency. That means it can link with
     "shared/nm-std-aux" and "shared/nm-glib-aux", but must not link
     with "shared/nm-udev-aux" (as it has no direct udev dependenct --
     although clients get it indirectly because libnm already requires
     it).

2) what is their overall purpose? As said, we rely on the linker to
   prune unused symbols. But in a few cases we avoid to merge different
   code in the same library. For example:

   - "shared/nm-glib-aux" and "shared/nm-base" both only have a
     glib2 dependency. Hence, they could be merged. However we
     don't do that because "shared/nm-base" is more about NetworkManager
     specific code, while "shared/nm-glib-aux" is about general
     purpose helpers.

3) some of these libraries are forked from an upstream. They are kept
   separate so that we can re-import future upstream versions.

Detail
======

- `shared/c-list`
- `shared/c-rbtree`
- `shared/c-siphash`
- `shared/c-stdoux`
- `shared/n-acd`
- `shared/n-dhcp4`

   These are forked from upstream and imported with git-subtree. They
   in general only have a libc dependency (or dependencies between each
   other).

- `shared/nm-std-aux`

   This contains helper code with only a libc dependency.
   Almost all C code depends on this library.

- `shared/nm-glib-aux`

   Like "shared/nm-std-aux" but also has a glib2 dependency.
   Almost all glib2 code depends on this library.

- `shared/nm-udev/aux`

   Like "shared/nm-glib-aux" but also has a libudev dependency. It
   has code related to libudev.

- `shared/systemd`

   These are forked from upstream systemd and imported with a script.
   Under "shared/systemd/src" we try to keep the sources as close to
   the original as possible. There is also some adapter code to make
   it useable for us. It has a dependency on "shared/nm-glib-aux"
   and will need a logging implementation for "shared/nm-glib-aux/nm-logging-fwd.h".

- `shared/nm-base`

   Depends on "shared/nm-glib-aux" and glib2 but it provides helper code
   that more about NetworkManager specifc things.

- `shared/nm-log-core`

   This is the logging implementation as used by NetworkManager core ("src/").
   It is also a dependency for "shared/nm-platform".

- `shared/nm-platform`

   Platform implementation. It depends on "shared/nm-log-core", "shared/nm-base"
   and "shared/nm-glib-aux".

- Other than that, there are still a few unorganized files/directories here.
  These should be cleaned up.
