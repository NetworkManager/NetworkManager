Upstream backports
---------------------------

There are situations where it is necessary to backport a patch to an earlier
version of NetworkManager.

In order to do the backport, use  `git cherry-pick -x`. Please use the commit
from the later branch. If the commit is not on that branch then it is also
necessary to backport to that branch.

Example:

We want to backport commit `323e18276894591712a5e29f6e907562c79c5216` from
`main` (1.33) branch to `nm-1-30` branch. In order to do that, we must search
if this bug has been backported to 1.32.

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
`c94b1c43d4b5c5b88d67d7966d23a005028e78d8`.

### Resolving conflicts

To find conflicts when doing a backporting in NetworkManager is very common but
we do not resolve the conflicts manually. Instead, we abort the current
cherry-pick and search for the commit that introduced the changes that are
causing the conflict and backport it too.

We only resolve the conflict manually if the extra commit introduces a lot of
unnecessary changes or excesive code changes which is not common.

### Backporting API

NetworkManager allow the users to build their application against latest stable
release and then run it against a newer release without relinking. If we want
to backport a new API from main (1.33) to nm-1-30, we need to do something
similar to `57c1982867609bf759fce202a172ceeb51a21d5f` in main and nm-1-32
branch.

Example:

An user wants to backport `05f2a0b0247ee4aa3da371658f310bc655cbf1af` from main
branch to `nm-1-30` branch. In this case, the user will need to write
`ec8df200f682c6726c1da624b5ae3984c4991056` and
`af00e39dd24644b8c979258e5579b43b88364d2f`.
