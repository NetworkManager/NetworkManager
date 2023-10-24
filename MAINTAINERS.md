Triaging issues
---------------

Issue tracker: https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/issues

Help other maintainers with the triage following these guidelines. This way, it
will be easier to find issues that require attention.

- Assign an issue to yourself if you are going to take care of providing the
  required help. Assign it to another person if he/she is more suitable to help,
  but do this quite rarely so we take care of not overloading to anyone.

- Add suitable labels to indicate the state of open issues:

  - `need-info`: waiting for info or feedback from anyone.

  - `need-discussion`: something is not clear about what to do, or about if
    something has to be done at all. The problem should be discussed by the
    maintainers and/or with the reporter and/or other interested parts.

  - `triaged`: if the problem is properly explained and understood. Add also
    one of the labels `bug` or `RFE` as corresponds.
  
  - `help-wanted`: request external contributors to work on this. If it's a
    simple fix, add `good-first-issue` too.

  - `work-in-progress`: anyone is already working on a Merge Request, so others.

  - `blocked`: the issue is waiting for something that blocks its progress

  - `close-proposed`: there are good reasons to reject the request (explain
    those reasons when adding the label). If after a reasonable time there is no
    additional info that is good enouch to reconsider it, the issue will be
    closed.  
    It is not mandatory to always use this tag before closing an issue, but
    usually desirable.

- Close an issue if the problem is already solved, either via a code fix or via
  some information that has been provided. Also if the request is clearly
  incorrect or doesn't fit at all in the project.


Merging Merge Requests
----------------------

- almost all new code, gets merged to `main` branch only. Stable branches only
  receive backports via `git cherry-pick -x`.

- almost always, make sure that the merge request is rebased against current
  `main` branch.

- if the merge request contains multiple patches, create a `--no-ff` merge
  request that envelop the patches. The merge commit can have a trivial commit
message like "area: merge branch 'xy/topic'" and refer to all relevant
resources. At least the full URL to the gitlab merge request should be there.

- for single patches, the merge commit can be skipped. In that case, add the
  full URL to the commit message before merging.

- before merging the result to `main`, make again sure that the merge request
  is up-to date (in particular, if you just rebased the branch or amended the
commit message). So usually first do a `git push origin -f -o ci.skip` to
update the merge request one more time, and the push the merge request to
`main`. The result is that the merge request in gitlab is shown as "Merged".

- always refer to relevant URLs (bugzilla, gitlab issues, gitlab merge
  request).  Do so via full URLs, not abbreviations like "!XYZ", so that the
URL is clickable in the browser.  Note that while the merge request is still
under review and being reworked, we will frequently force push the branch.
Gitlab and github will create backlinks to full URLs, so we want not to specify
those URLs while development, but the moment before merging, we will add them.
This means, usually when we decide that a merge request is ready to be merged,
we still need to rebase it to latest main and amend the commit messages. Then
we usually need to push once more to the merge-request, before pushing the
final result to `main`.

The purpose of this elaborate scheme is to get a clean history that is easy
to review and links to relevant resources.

If you forget to mention an URL, you can do so afterwards via `git-notes`.
See [CONTRIBUTING.md](CONTRIBUTING.md#git-notes-refsnotesbugs).


Upstream backports
---------------------------

There are situations where it is necessary to backport a patch to an earlier
version of NetworkManager.

In order to do the backport, use `git cherry-pick -x`. Please use the commit
from the next stable branch. If the commit is not on that branch then it is also
necessary to backport to that branch.

Example:

We want to backport commit 323e18276894591712a5e29f6e907562c79c5216 from `main`
(1.33) branch to `nm-1-30` branch. In order to do that, we must search if this
bug has been backported to 1.32.

`git log --all --grep "323e18276894591712a5e29f6e907562c79c5216"`

In case the backport to 1.32 is missing it would not show anything so please do
the backport to 1.32 first.

If the backport is done, the output should be similar to:

```
commit c94b1c43d4b5c5b88d67d7966d23a005028e78d8
Author: Thomas Haller <thaller@redhat.com>
Date:   Wed Sep 1 09:30:29 2021 +0200

    cloud-setup: return structure for get_config() result instead of generic hash table

    Returning a struct seems easier to understand, because then the result
    is typed.

    Also, we might return additional results, which are system wide and not
    per-interface.

    (cherry picked from commit 323e18276894591712a5e29f6e907562c79c5216)
```

In this case, the commit that should be backported is
c94b1c43d4b5c5b88d67d7966d23a005028e78d8.

### Resolving conflicts

To find conflicts when doing a backporting in NetworkManager is very common but
we do not resolve the conflicts manually. Instead, we abort the current
cherry-pick and search for the commit that introduced the changes that are
causing the conflict and backport it too.

We only resolve the conflict manually if the extra commit introduces a lot of
unnecessary changes or excesive code changes which is not common.

### Backporting API

NetworkManager allows the users to build their application against the latest
stable release and then run it against a newer release without relinking. To
allow this, we need to guarantee that after we release a version that includes a
new libnm linker version, then any release done after that point with a higher
version number contains that linker version with the same symbols.

In practice when we want to backport new API from main we have two options:

- if the new API hasn't been included in a stable release of NetworkManager,
  then we can just backport the API to the old branch and pretend it was
  introduced there. For example, 8763e6da9c5adb3c4ccf3b2713dbcc25a91c5ede
  introduces new API on main during the 1.21 development cycle; 1.22 is not
  released yet. Then the symbol is backported to nm-1-20 before 1.20.6 with
  commit 90671a30b771d418953bd021d50c3cc43f253e6e. The symbol on main branch is
  then adjusted with 551fd3e28f6b142bd57eefacfaf96b8fb8e309dd. Note that at this
  point 1.20.6 must be released before 1.22.0.

- if the new API is already included in a stable release, we backport the API to
  the old branch and then duplicate the symbol on main with both versions. For
  example, 2e2ff6f27aa1bfa7a27d49980b319873240ec84b introduces new API on main,
  which is released as 1.12.0. The API is backported to 1.10.14 in commit
  19d7e66099ee43f47d6be0e740dc710fc365d200. Then, on main we add duplicate
  symbols with commit 5eade4da11ee38a0e7faf4a87b2c2b5af07c5eeb.

### Reimporting systemd

See [here](src/libnm-systemd-shared/README.md#reimport-upstream-code).

### Copr repository

See [here](contrib/scripts/nm-copr-build.sh).

### gitlab-ci Pipelines

See [here](.gitlab-ci/README.md).
