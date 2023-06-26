libnm-systemd-shared
====================

This is a fork of systemd source files that are compiled as a static library
with general purpose helpers.

We mainly need this for [../libnm-systemd-core/](../libnm-systemd-core/), which
contains builds network tools that we use (our internal DHCPv6 library).

We should not use systemd directly from our sources, beyond what we really need
to make get libnm-systemd-core working. That means, although the systemd code
contains many useful utility functions, we should not use them beyond what we
really need, because one day we want to drop this code again.


Reimport Upstream Code
----------------------

We want to avoid deviations in our fork, and frequently re-import latest
systemd version (every 4 to 8 weeks). The reason is that we frequently should
check whether important fixes were done in upstream systemd, and the effort of
doing that check is half the work of a full reimport.  Also, by reimporting
frequently, we avoid deviating hugely and fall back too much.

Of course this is cumbersome. We therefore should avoid using the systemd code
as much as we can, and work towards dropping it altogether.

To do a re-import, do:

- checkout `systemd` branch.

- Use the last commit message (`git commit --allow-empty -C origin/systemd`).
  Then modify the commit message (`git commit --allow-empty --amend`). The
  commit message contains a long script that is used to re-import the code.
  Adjust the script in the commit message, and run it. Commit the changes on
  `systemd` branch.

- checkout `main` branch, and `git merge systemd`. Fix all issues, test,
  repeat.

- open merge request, check that all tests pass. In particular, enable build on
  all test distributions in gitlab-ci.

- push `main` and `systemd` branches. Compare how it was done during past imports.

### Hints

- Eagerly commented out unused functions definitions with `#if 0` and `#endif`.
- Patching header files is best avoided and keep function declarations.
- We may create some dummy header files in `src/libnm-systemd-{shared,core}/sd-adapt-\*/`
  if that is a suitable way to get the code to compile, while having minimal modifications
  to systemd code.
- Let git be aware of the merge history. Git can help you to better resolve merge conflicts.
  For example, a plain rebase of the branch on `main` will result in conflicts. Instead,
  create a temporary branch and merge the code (no rebase). With the help of the history,
  git will not run into conflicts during merging. Then, the merged git-tree contains the
  desired content of the files.
