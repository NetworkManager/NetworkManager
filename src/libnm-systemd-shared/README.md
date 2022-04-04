libnm-systemd-shared
====================

This is a fork of systemd source files that are compiled
as a static library with general purpose helpers.

We mainly need this for [../libnm-systemd-core/](../libnm-systemd-core/),
which contains systemd library with network tools (like DHCPv6).

We should not use systemd directly from our sources, beyond what
we really need to make get libnm-systemd-core working.


Reimport Upstream Code
----------------------

We want to avoid deviations in our fork, and frequently re-import
latest systemd version (every 4 to 8 weeks). The reason is that we
frequently should check whether important fixes were done in upstream
systemd, and the effort of doing that is half the work of just reimporting.
Also, by reimporting frequently, we avoid deviating hugely (instead we only deviate
largely).

Of course this is cumbersome. We should replace systemd code with something else.

To do a re-import, do:

- checkout `systemd` branch.

- Use the last commit message (`git commit --allow-empty -C origin/systemd`).
  Then modify the commit message (`git commit --allow-empty --amend`). The
  commit message contains a long script that is used to re-import the code.
  Adjust the script in the commit message, and run it. Commit the changes on
  `systemd` branch.

- checkout `main` branch, and `git merge systemd`. Fix all issues, test,
  repeat.

- open merge request, check that all tests pass. In particular, enable build
  on all test distributions.

- push `main` and `systemd` branch.
