#!/bin/bash

# environment variables:
# - GIT_REF: the ref that should be build. Can be "main" or a git sha.
# - DEBUG: set to 1 to build "--with debug".
# - NM_GIT_BUNDLE: set to a HTTP url where to fetch the nm-git-bundle-*.noarch.rpm
#     from. Set to empty to skip it. By default, it fetches the bundle from copr.

set -ex

if [[ "$DEBUG" == 1 ]]; then
    DEBUG="--with debug"
else
    DEBUG="--without debug"
fi

if [[ -z "$GIT_REF" ]]; then
    echo "\$GIT_REF is not set!"
    exit 1
fi

mkdir NetworkManager
pushd NetworkManager
git init .

git remote add origin https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git
git remote add --no-tags github https://github.com/NetworkManager/NetworkManager

get_nm_git_bundle() {
    # try to fetch the refs from nm-git-bundle.
    #
    # This script runs in copr infrastructure to create the SRPM.
    # The idea is that this URL is close and downloading it is cheaper
    # than fetching everything from upstream git.
    if [ -z "$NM_GIT_BUNDLE" ]; then
        if [ -n "${NM_GIT_BUNDLE+x}" ]; then
            return 0
        fi
        NM_GIT_BUNDLE='https://download.copr.fedorainfracloud.org/results/networkmanager/NetworkManager-main/fedora-34-x86_64/02112661-nm-git-bundle/nm-git-bundle-20210401-201640.noarch.rpm'
    fi
    mkdir nm-git-bundle
    pushd nm-git-bundle
    time curl "$NM_GIT_BUNDLE" \
      | rpm2cpio - \
      | cpio -idmv
    popd
    git remote add nm-git-bundle "$PWD/nm-git-bundle/usr/share/NetworkManager/nm-git-bundle.git"
    git fetch nm-git-bundle
}

get_nm_git_bundle
git fetch github
git fetch origin
git remote remove nm-git-bundle || true

GIT_SHA="$(git show-ref --verify --hash "$GIT_REF" 2>/dev/null ||
           git show-ref --verify --hash "refs/remotes/origin/$GIT_REF" 2>/dev/null ||
           git rev-parse --verify "$GIT_REF^{commit}" 2>/dev/null)"

git checkout -b tmp "$GIT_SHA"

./contrib/fedora/rpm/build_clean.sh -g -S -w test $DEBUG -s copr
popd

mv ./NetworkManager/contrib/fedora/rpm/latest/{SOURCES,SPECS}/* .
rm -rf ./NetworkManager
