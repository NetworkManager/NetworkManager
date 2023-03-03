#!/bin/bash

# In our git repository we vendor in several external projects.
# We do so via git-subtree.
#
# Run this script (without arguments) for re-importing the latest
# version of those projects.
#
# You can also specify the projects to reimport on the command line,
# ./contrib/scripts/git-subtree-reimport.sh  [ c-list | c-rbtree | c-siphash | c-stdaux | n-acd | n-dhcp4 ... ]

set -e

cd "$(dirname "$(readlink -f "$0")")/../.."

reimport() {
    local d="$1"
    local project
    local branch

    if [[ "$d" = c-* ]] ; then
        project=c-util
        branch=main
    else
        project=nettools
        branch=master
    fi

    CMD=( git subtree pull --prefix "src/$d" "git@github.com:$project/$d.git" "$branch" --squash -m \
"$d: re-import git-subtree for 'src/$d'

  git subtree pull --prefix src/$d git@github.com:$project/$d.git $branch --squash
" )

    printf '\n>>>> %s >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n' "$d"
    printf '>>>'
    for c in "${CMD[@]}"; do
        printf ' %q' "$c"
    done
    printf '\n'

    "${CMD[@]}" 2>&1

    local REMOTE_COMMIT="$(git rev-parse FETCH_HEAD)"

    echo ">>>>> RESULT:"
    printf ">>> git diff %s: HEAD:src/%s\n" "$REMOTE_COMMIT" "$d"
    GIT_PAGER=cat git diff --color=always "$REMOTE_COMMIT:" "HEAD:src/$d"
}

reimport_all() {
    local ARGS

    ARGS=( "$@" )
    if [ "${#ARGS[@]}" = 0 ]; then
        ARGS=( c-list c-rbtree c-siphash c-stdaux n-acd n-dhcp4 )
    fi
    for d in "${ARGS[@]}" ; do
        reimport "$d"
    done
}

reimport_all "$@"
