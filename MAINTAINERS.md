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
