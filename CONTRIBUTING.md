Guidelines for Contributing
===========================


Community
---------

Check out website https://networkmanager.dev and our [GNOME page](https://wiki.gnome.org/Projects/NetworkManager).

The release tarballs can be found at [download.gnome.org](https://download.gnome.org/sources/NetworkManager/).

Our mailing list is networkmanager-list@gnome.org ([archive](https://mail.gnome.org/archives/networkmanager-list/)).

Find us on IRC channel `#nm` on Libera.Chat.

Report issues and send patches via [gitlab.freedesktop.org](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/)
or our mailing list.


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


Coding Standard
---------------

The formatting uses clang-format with clang 11.0. Run
`./contrib/scripts/nm-code-format.sh -i` to reformat the code
or call `clang-format` yourself.
You may also call `./contrib/scripts/nm-code-format-container.sh`
which runs a Fedora 33 container using podman.
You are welcome to not bother and open a merge request with
wrong formatting, but note that we then will automatically adjust
your contribution before merging.

The automatic reformatting was done by commit 328fb90f3e0d4e35975aff63944ac0412d7893a5.
Use `--ignore-rev` option or `--ignore-revs-file .git-blame-ignore-revs` to ignore
the reformatting commit with git-blame:

```
$ git config --add 'blame.ignoreRevsFile' '.git-blame-ignore-revs'
```

Since our coding style is entirely automated, the following are just
some details of the style we use:

* Indent with 4 spaces. (_no_ tabs).

* Have no space between the function name and the opening '('.
  - GOOD: `g_strdup(x)`
  - BAD:  `g_strdup (x)`

* C-style comments
  - GOOD: `f(x);  /* comment */`
  - BAD:  `f(x);  // comment`

* Keep assignments in the variable declaration area pretty short.
  - GOOD: `MyObject *object;`
  - BAD:  `MyObject *object = complex_and_long_init_function(arg1, arg2, arg3);`

* 80-cols is a guideline, don't make the code uncomfortable in order to fit in
  less than 80 cols.

* Constants are CAPS_WITH_UNDERSCORES and use the preprocessor.
  - GOOD: `#define MY_CONSTANT 42`
  - BAD:  `static const unsigned myConstant = 42;`


Unit Tests
----------

We have plenty of unit tests. Run them with `make check` or
`meson -C "$BUILD_DIR" test`.

Note that some files in the source tree are both generated and commited
to git. That means, certain changes to the code also affect these generated
files. The unit test fail in that case, to indicate that the generated
files no longer match what is commited to git.
You can also automatically regenerate the files by running `NM_TEST_REGENERATE=1 make check`.
Note that test-client requires working translation.
See the [comment](https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/eee4332e8facfa5ff5940fa1655575d76ca143ea/src/tests/client/test-client.py#L19)
for how to configure it.


Assertions in NetworkManager code
---------------------------------

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


Git Notes (refs/notes/bugs)
---------------------------

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
$ git notes --ref refs/notes/bugs add -m "(cherry picked from $COMMIT_SHA)" HEAD
```

You should see the notes in git-log output as well.

To resync our local notes use:

```
$ git fetch origin refs/notes/bugs:refs/notes/bugs -f
```

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

`./src`- source code for libnm, nmcli, nm-cloud-setup, nmtui…

`./tools`- tools for generating the intermediate files or merging the file.

Cscope/ctags
---------------------------

NetworkManager's source code is large. It may be a good idea to use tools like cscope/ctags to index the
source code and navigate it. These tools can integrate with editors like `Vim` and `Emacs`. See:

- http://cscope.sourceforge.net/cscope_vim_tutorial.html
- https://www.emacswiki.org/emacs/CScopeAndEmacs
