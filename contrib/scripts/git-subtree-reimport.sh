#!/bin/bash

set -ex

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

    git subtree pull --prefix "src/$d" "git@github.com:$project/$d.git" "$branch" --squash -m \
"$d: re-import git-subtree for 'src/$d'

  git subtree pull --prefix src/$d git@github.com:$project/$d.git $branch --squash
"
}

reimport_all() {
    for d in c-list c-rbtree c-siphash c-stdaux n-acd n-dhcp4 ; do
        reimport "$d"
    done
}

reimport_all
