Guidelines for Contributing
===========================


Community
---------

Check out website https://networkmanager.dev and our [GNOME page](https://wiki.gnome.org/Projects/NetworkManager).

The release tarballs can be found at [download.gnome.org](https://download.gnome.org/sources/NetworkManager/).

Our mailing list is networkmanager@lists.freedesktop.org ([archive](https://lists.freedesktop.org/archives/networkmanager/),
[old-archive](https://mail.gnome.org/archives/networkmanager-list/)).

Find us on IRC channel `#nm` on Libera.Chat.

Report issues and send patches via [gitlab.freedesktop.org](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/)
or our mailing list.


Documentation
-------------

Find the documentation on [our website](https://networkmanager.dev/docs/).


Legal
-----

NetworkManager is partly licensed under terms of GNU Lesser General Public License
version 2 or later ([LGPL-2.1-or-later](COPYING.LGPL)). That is for example the case for libnm.
For historical reasons, the daemon itself is licensed under terms of GNU General
Public License, version 2 or later ([GPL-2.0-or-later](COPYING)). See the SPDX license comment
in the source files.

Note that all new contributions to NetworkManager **MUST** be made under terms of
LGPL-2.1-or-later, that is also the case for files that are currently licensed GPL-2.0-or-later.
The reason is that we might one day use the code under terms of LGPL-2.1-or-later and all
new contributions already must already agree to that.
For more details see [RELICENSE.md](RELICENSE.md).

Do not use "Signed-off-by:" lines in commits for NetworkManager. It has no meaning.


Coding Style
------------

### clang-format

The formatting is automated using [clang-format](https://clang.llvm.org/docs/ClangFormat.html).
Run `./contrib/scripts/nm-code-format.sh -i` ([[1]](contrib/scripts/nm-code-format.sh)) to reformat
the code or run `clang-format` directly.

As the generated format depends on the version of clang-format, you need to use the
correct clang-format version. That is basically the version that our [gitlab-ci
pipeline](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/pipelines) uses
for the "check-tree" test. This is the version from a recent Fedora installation.

You may also run `./contrib/scripts/nm-code-format-container.sh` which uses a
Fedora container with podman and the correct version of clang-format.

You are welcome to not bother and open a merge request with wrong formatting,
but note that we then will automatically adjust your contribution before
merging.

The automatic reformatting was done by commit 328fb90f3e0d4e35975aff63944ac0412d7893a5.
Use `--ignore-rev` option or `--ignore-revs-file .git-blame-ignore-revs` to ignore
the reformatting commit with git-blame:

```
$ git config --add 'blame.ignoreRevsFile' '.git-blame-ignore-revs'
```

You may integrate clang-formatter in your editor (for [vim](https://github.com/rhysd/vim-clang-format)).

### Style

As we use clang-format, our style is in parts determined by the tool.
Run the tool to format the code. See the earlier point.

The formatting tool cannot cover all questions. The most important rule is
to mimic the existing code and *imitate the surrounding style*.

In general, we require to build without compiler warnings, for the warnings
that we enable. Our language is C11 with some GCC-isms (like typeof(),
expression statements, cleanup attribute). In practice, we support various versions
of GCC and clang. The supported C "dialect", compilers and libc are those that we
can practically build and test in our CI. We don't target a theoretical, pure C11/POSIX
standard or a libc/compiler that we cannot test.
Patches for making NetworkManager more portable are welcome, if there is a
practical use and checked by CI. Glibc and musl libc are supported.

We follow a mixture of [glib's](https://developer.gnome.org/documentation/guidelines/programming/coding-style.html)
and [systemd's](https://github.com/systemd/systemd/blob/main/docs/CODING_STYLE.md) style, which already have extensive
guidelines. Following there are a few noteworthy points.

* Use cleanup functions (`gs_free`, `gs_*`, `nm_auto*`) to let a stack
  variable own a resource instead of explicit free. Combine them with
  `g_steal_pointer()` to transfer ownership and with clear functions
  (`g_clear_object()`, `nm_clear_g_free()`, `nm_clear*()`) to destroy
  the resource early.

* Use `GSource` instances instead of the source IDs from `g_idle_add()`, `g_timeout_add()`,
  etc. Possibly use `nm_g_idle_add_source()`, `nm_g_timeout_add_source()`, etc.
  and combine with `nm_clear_g_source_inst()`.

* Don't use `GDBusProxy` or `GDBusObjectManager`. Use plain `GDBusConnection`.

* Names in our header files should always have an "nm" prefix (like "nm_",
  "NM_", "_nm_", "_nmp_"). Names in source files usually should not have an
  "nm" prefix.

* Indent with spaces. (_no_ tabs).

* C-style comments
  - GOOD: `f(x);  /* comment */`
  - BAD:  `f(x);  // comment`

* Keep assignments in the variable declaration area pretty short.
  - GOOD: `MyObject *object;`
  - BAD:  `MyObject *object = complex_and_long_init_function(arg1, arg2, arg3);`

* Declare each variable on a separate line:
  - BAD: `int i, j;`

* Constants are CAPS_WITH_UNDERSCORES and use the preprocessor.
  - GOOD: `#define MY_CONSTANT 42`
  - BAD:  `static const unsigned myConstant = 42;`

* Always use curly braces for blocks that span multiple lines. For single lines
  the braces may be omitted, but are not prohibited.

### Checkpatch

We have a [checkpatch.pl](contrib/scripts/checkpatch.pl) script, which is
also run in our gitlab-ci. Review the warnings, but as these are just heuristics,
there might be valid reasons to reject them. There is also a
[git hook](contrib/scripts/checkpatch-git-post-commit-hook) which you can call
from `.git/hooks/post-commit`.


Building from Source
--------------------

First see that you have the required build dependencies. For Fedora/RHEL/Centos,
you can look at [this](contrib/fedora/REQUIRED_PACKAGES)
script and [here](contrib/debian/REQUIRED_PACKAGES)
is a script for Debian/Ubuntu.

Both meson and autotools are supported. You may choose whatever you prefer.
For autotools the common steps are

```
./autogen.sh $CONFIGURE_OPTIONS
make -j 8
# optional: sudo make install
```
and for meson it's
```
meson build $CONFIGURE_OPTIONS
ninja -C build
# optional: sudo meson install -C build
```

Beware to set the correct `$CONFIGURE_OPTIONS`. In particular, you may
not want the default installation prefix and not overwrite files in
`/usr`.

### Fedora

For Fedora/RHEL/CentOS, you can build an RPM from upstream sources with
```
   ./contrib/fedora/rpm/build_clean.sh -r
```
Pass `--help` to [build_clean.sh](contrib/fedora/rpm/build_clean.sh) for options.

You may also use the [Copr project](https://copr.fedorainfracloud.org/coprs/networkmanager/)
maintained by the upstream maintainers. There you find builds of latest `main` and stable branches.


Unit Tests
----------

We have plenty of unit tests. Run them with `make check` or
`meson test -C build`.

Note that some files in the source tree are both generated and commited
to git. That means, certain changes to the code also affect these generated
files. The unit test fail in that case, to indicate that the generated
files no longer match what is commited to git.
You can also automatically regenerate the files by running `NM_TEST_REGENERATE=1 make check`.
Note that test-client requires working translation.
See the [comment](src/tests/client/test-client.py#L14)
for how to configure it.


Code Structure
---------------------------

`./contrib`- Contains a lot of required package, configuration for different platform and environment, build NM from source tree.

`./data`- Contains some configurations and rules.

`./docs`- Contains the generated documentation for libnm and for the D-Bus API.

`./examples`- Some code examples for basic networking operations and status checking.

`./introspection`- XML docs describing various D-Bus interface and their properties.

`./m4`- Contains M4 macros source files for autoconf.

`./man`- NM manual files.

`./po`- contains text-based portable object file. These .PO files are referenced by GNU gettext as a property file and these files are human readable used for translating purpose.

[`./src`](src/)- source code for libnm, nmcli, nm-cloud-setup, nmtui…

`./tools`- tools for generating the intermediate files or merging the file.

Cscope/ctags
---------------------------

NetworkManager's source code is large. It may be a good idea to use tools like cscope/ctags to index the
source code and navigate it. These tools can integrate with editors like `Vim` and `Emacs`. See:

- http://cscope.sourceforge.net/cscope_vim_tutorial.html
- https://www.emacswiki.org/emacs/CScopeAndEmacs

For cscope, you can also set `$SOURCEDIRS` to include other source trees and navigate
those sources. For example,
```
export SOURCEDIRS=/path/to/glib:/path/to/libndp
cscope -b -q -R -ssrc
```


Miscellaneous
---------------------------

### Assertions in NetworkManager code

There are different kind of assertions. Use the one that is appropriate.

1) `g_return_*()` from glib. This is usually enabled in release builds and
  can be disabled with `G_DISABLE_CHECKS` define. This uses `g_log()` with
  `G_LOG_LEVEL_CRITICAL` level (which allows the program to continue,
  unless `G_DEBUG=fatal-criticals` or `G_DEBUG=fatal-warnings` is set). As such,
  this is usually the preferred way for assertions that are supposed to be
  enabled by default. \
  \
  Optimally, after a `g_return_*()` failure the program can still continue. This is
  also the reason why `g_return_*()` is preferable over `g_assert()`.
  For example, that is often not the case for functions that return a `GError`, because
  `g_return_*()` will return failure without setting the error output. That often leads
  to a crash immediately after, because the caller requires the `GError` to be set.
  Make a reasonable effort so that an assertion failure may allow the process
  to proceed. But don't put too much effort in it. After all, it's an assertion
  failure that is not supposed to happen either way.

2) `nm_assert()` from NetworkManager. This is disabled by default in release
  builds, but enabled if you build `--with-more-assertions`. See the `WITH_MORE_ASSERTS`
  define. This is preferred for assertions that are expensive to check or
  nor necessary to check frequently. It's also for conditions that can easily
  be verified to be true and where future refactoring is unlikely to break the
  invariant.
  Use such asserts deliberately and assume they are removed from production builds.

3) `g_assert()` from glib. This is used in unit tests and commonly enabled
  in release builds. It can be disabled with `G_DISABLE_ASSERT` define.
  Since such an assertion failure results in a hard crash, you
  should almost always prefer `g_return_*()` over `g_assert()` (except in unit tests).

4) `assert()` from C89's `<assert.h>`. It is usually enabled in release builds and
  can be disabled with `NDEBUG` define. Don't use it in NetworkManager,
  it's basically like g_assert().

5) `g_log()` from glib. These are always compiled in, depending on the logging level
  they act as assertions too. `G_LOG_LEVEL_ERROR` messages abort the program, `G_LOG_LEVEL_CRITICAL`
  log a critical warning (like `g_return_*()`, see `G_DEBUG=fatal-criticals`)
  and `G_LOG_LEVEL_WARNING` logs a warning (see `G_DEBUG=fatal-warnings`).
  `G_LOG_LEVEL_DEBUG` level is usually not printed, unless `G_MESSAGES_DEBUG` environment
  variable enables it. \
  \
  In general, avoid using `g_log()` in NetworkManager. We have nm-logging instead
  which logs to syslog or systemd-journald.
  From a library like libnm it might make sense to log warnings (if something
  is really wrong) or debug messages. But better don't. If it's important,
  find a way to report the condition via the API to the caller. If it's
  not important, keep silent.
  In particular, don't use levels `G_LOG_LEVEL_CRITICAL` and `G_LOG_LEVEL_WARNING` because
  we treat them as assertions and we want to run all out tests with `G_DEBUG=fatal-warnings`.

6) `g_warn_if_*()` from glib. These are always compiled in and log a `G_LOG_LEVEL_WARNING`
  warning. Don't use this.

7) `G_TYPE_CHECK_INSTANCE_CAST()` from glib. Unless building with `WITH_MORE_ASSERTS`,
  we set `G_DISABLE_CAST_CHECKS`. This means, cast macros like `NM_DEVICE(ptr)`
  translate to plain C pointer casts. Use such cast macros deliberately, in production
  code they are cheap, with more asserts enabled they check that the pointer type is
  suitable.

Of course, every assertion failure is a bug, and calling it must have no side effects.

Theoretically, you are welcome to set `G_DISABLE_CHECKS`, `G_DISABLE_ASSERT` and
`NDEBUG` in production builds. In practice, nobody tests such a configuration, so beware.

For testing, you also want to run NetworkManager with environment variable
`G_DEBUG=fatal-warnings` to crash upon `G_LOG_LEVEL_CRITICAL` and `G_LOG_LEVEL_WARNING`
`g_log()` message. NetworkManager won't use these levels for regular logging
but for assertions.


### Header Includes

Almost all C source header should include a certain set of default headers.
That comes from the fact, that (almost) all source should include autotools' `"config.h"`
as first.

That means, (almost) all our C sources should start with
```C
/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "$BASE/nm-default$EXTRA.h"
```
that is, the first header is one of the several `"*/nm-default*.h"` headers.
This header ensure that certain headers like [`libnm-std-aux/nm-std-aux.h`](src/libnm-std-aux/nm-std-aux.h)
and basics like `nm_assert()` and `nm_auto_g_free` are available everywhere.

The second include is the header that belongs to the C source file. This
is so that header files are self-contained (aside what default dependencies that
they get and everybody can rely on).

The next includes are system headers with `<>`. Exceptions are headers like
"libnm-std-aux/nm-linux-compat.h" and "nm-compat-headers/\*" which are our small
wrappers around system headers. These are also to be included together with system
headers.

Finally, all other headers from our source tree. Note that all build targets
have `-I. -I./src/` in their build arguments. So to include a header like
[`src/libnm-glib-aux/nm-random-utils.h`](src/libnm-glib-aux/nm-random-utils.h)
you'd do `#include "libnm-glib-aux/nm-random-utils.h"`.

Note that there are exceptions. For example, `src/libnm-std-aux/nm-linux-compat.h`](src/libnm-std-aux/nm-linux-compat.h)
may need to be included before system headers as it is supposed to include headers
from `src/linux-headers`](src/linux-headers).

See an example [here](src/core/nm-manager.c#L1).

### GObject Properties

We use GObjects and GObject Properties in various cases. For example:

1. In public API in libnm they are used and useful for providing a standard
   GObject API. One advantage of GObject properties is that they work well
   with introspection and bindings.

1. `NMSetting` properties commonly are GObject properties. While we provide
   C getters, they commonly don't have a setter. That is, settings can often
   only set via `g_object_set()`.

1. Our D-Bus API uses glue code. For the daemon, this is
   [`nm-dbus-manager.[ch]`](src/core/nm-dbus-manager.c) and
   [`nm-dbus-object.[ch]`](src/core/nm-dbus-object.c). For libnm's
   `NMClient`, this is [`nm-object.c`](src/libnm-client-impl/nm-object.c).
   These bindings rely on GObject properties.

1. Sometimes it is convenient to use the functionality that GObject
   properties provide. In particular, `notify::` property changed signals
   or the ability to freeze/thaw the signals.

1. Immutable objects are great, so there is a desire to have `G_PARAM_CONSTRUCT_ONLY`
  properties. In that case, avoid adding a getter too, the property only needs to be
  writable and you should access it via the C wrapper.

In general, use GObject properties sparsely and avoid them (unless you need them for one of the
reasons above).

Almost always add a `#define` for the property name, and use for example
`g_signal_connect(obj, "notify::"NM_TARGET_SOME_PROPERTY", ...)`. The goal is to
be able to search the use of all properties.

Almost always add C getter and setters and prefer them over `g_object_get()`
and `g_object_set()`. This also stresses the point that you usually wouldn't use
a GObject property aside the reasons above.

When adding a GObject properties, do it for only one of the reasons above.
For example, the property `NM_MANAGER_DEVICES` in the daemon is added to bind
the property to D-Bus. Don't use that property otherwise and don't register
a `notify::NM_MANAGER_DEVICES` for your own purpose. The reason is that GObject
properties are harder to understand and they should be used sparsely and for
one specific reason.

### Git Notes (refs/notes/bugs)

We use special tags in commit messages like "Fixes", "cherry picked from" and "Ignore-Backport".
The [find-backports](contrib/scripts/find-backports) script uses these to find patches that
should be backported to older branches. Sometimes we don't know a-priory to mark a commit
with these tags so we can instead use the `bugs` notes.

The git notes reference is called "refs/notes/bugs".

So configure:

```
$ git config --add 'remote.origin.fetch' 'refs/notes/bugs:refs/notes/bugs'
$ git config --add 'notes.displayref' 'refs/notes/bugs'
```

For example, set notes with

```
$ git notes --ref refs/notes/bugs add -m "(cherry picked from commit $COMMIT_SHA)" HEAD
```

You should see the notes in git-log output as well.

To resync our local notes use:

```
$ git fetch origin refs/notes/bugs:refs/notes/bugs -f
```
### Testing NetworkManager with nm-in-container script.

See [the readme](tools/nm-in-container/README.md) for details.
