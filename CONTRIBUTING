Guidelines for Contributing
===========================


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


Legal
-----

NetworkManager is partly licensed under terms of GNU Lesser General Public License
version 2 or later (LGPL-2.1+). That is for example the case for libnm.
For historical reasons, the daemon itself is licensed under terms of GNU General
Public License, version 2 or later (GPL-2.0+). See the license comment in the source
files.
Note that all new contributions to NetworkManager MUST be made under terms of
LGPL-2.1+, that is also the case for parts that are currently licensed GPL-2.0+.
The reason for that is that we might eventually relicense everything as LGPL and
new contributions already must agree with that future change.
For more details see [RELICENSE.md](RELICENSE.md).


Assertions in NetworkManager code
---------------------------------

There are different kind of assertions. Use the one that is appropriate.

1) g_return_*() from glib. This is usually enabled in release builds and
  can be disabled with G_DISABLE_CHECKS define. This uses g_log() with
  G_LOG_LEVEL_CRITICAL level (which allows the program to continue,
  unless G_DEBUG=fatal-criticals or G_DEBUG=fatal-warnings is set). As such,
  this is usually the preferred way for assertions that are supposed to be
  enabled by default.

  Optimally, after a g_return_*() failure the program can still continue. This is
  also the reason why g_return_*() is preferable over g_assert().
  For example, that is often not given for functions that return a GError, because
  g_return_*() will return failure without setting the error output. That often leads
  to a crash immidiately after, because the caller requires the GError to be set.
  Make a reasonable effort so that an assertion failure may allow the process
  to proceed. But don't put too much effort in it. After all, it's an assertion
  failure that is not supposed to happen either way.

2) nm_assert() from NetworkManager. This is disabled by default in release
  builds, but enabled if you build --with-more-assertions. See "WITH_MORE_ASSERTS"
  define. This is preferred for assertions that are expensive to check or
  nor necessary to check frequently. It's also for conditions that can easily
  verified to be true and where future refactoring is unlikley to break that
  condition.
  Use this deliberately and assume it is removed from production builds.

3) g_assert() from glib. This is used in unit tests and commonly enabled
  in release builds. It can be disabled with G_DISABLE_ASSERT assert
  define. Since this results in a hard crash on assertion failure, you
  should almost always prefer g_return_*() over this (except in unit tests).

4) assert() from <assert.h>. It is usually enabled in release builds and
  can be disabled with NDEBUG define. Don't use it in NetworkManager,
  it's basically like g_assert().

5) g_log() from glib. These are always compiled in, depending on the logging level
  these are assertions too. G_LOG_LEVEL_ERROR aborts the program, G_LOG_LEVEL_CRITICAL
  logs a critical warning (like g_return_*(), see G_DEBUG=fatal-criticals)
  and G_LOG_LEVEL_WARNING logs a warning (see G_DEBUG=fatal-warnings).
  G_LOG_LEVEL_DEBUG level is usually not printed, unless G_MESSAGES_DEBUG environment
  is set.
  In general, avoid using g_log() in NetworkManager. We have nm-logging instead
  which logs to syslog/systemd-journald.
  From a library like libnm it might make sense to log warnings (if someting
  is really wrong) or debug messages. But better don't. If it's important,
  find a way to report the notification via the API to the caller. If it's
  not important, keep silent.
  In particular, don't use levels G_LOG_LEVEL_CRITICAL and G_LOG_LEVEL_WARNING because
  these are effectively assertions and we want to run with G_DEBUG=fatal-warnings.

6) g_warn_if_*() from glib. These are always compiled in and log a G_LOG_LEVEL_WARNING
  warning. Don't use this.

7) G_TYPE_CHECK_INSTANCE_CAST() from glib. Unless building with "WITH_MORE_ASSERTS",
  we set G_DISABLE_CAST_CHECKS. This means, cast macros like NM_DEVICE(ptr)
  translate to plain C pointer casts. Use such cast macros deliberately, in production
  code they are cheap, with more asserts enabled the check that the pointer type is
  suitable.

Of course, every assertion failure is a bug, and calling it must have no side effects.

Theoretically, you are welcome to disable G_DISABLE_CHECKS and G_DISABLE_ASSERT
in production builds. In practice, nobody tests such a configuration, so beware.

For testing, you also want to run NetworkManager with environment variable
G_DEBUG=fatal-warnings to crash upon G_LOG_LEVEL_CRITICAL and G_LOG_LEVEL_WARNING
g_log() message. NetworkManager won't use these levels for regular logging
but for assertions.


Git Notes (refs/notes/bugs)
---------------------------

There are special notes to annotate git commit messages with information
about "Fixes" and "cherry picked from". Annotating the history is useful
if it was not done initially because our scripts can make use of it.

The notes it are called "refs/notes/bugs".

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
