#!/bin/bash

# This is the build script used by our copr repository at
#   https://copr.fedorainfracloud.org/coprs/networkmanager
#
# On a new upstream release, add new copr jobs named "NetworkManager-X.Y" and
# "NetworkManager-X.Y-debug".
#
#   - best, look at the latest copr project and replicate the settings.
#   - add a custom build with the following script:
#
#        #!/bin/bash
#        export GIT_REF=nm-$X-$Y
#        export DEBUG=0/1
#        export LTO=
#        curl https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/raw/main/contrib/scripts/nm-copr-build.sh | bash
#
#   - for certain CentOS/EPEL you need to add https://copr.fedorainfracloud.org/coprs/nmstate/nm-build-deps/
#     as build chroot. See under "Settings/Project Details" for the latest copr project.
#   - go to "Settings/Integrations" and find the notification URL for the project. Then
#     go to https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/hooks and add
#     a push event for the "nm-$X-$Y" branch.
#
# environment variables for this script:
# - GIT_REF: the ref that should be build. Can be "main" or a git sha.
# - DEBUG: set to 1 to build "--with debug". Otherwise the default is a release
#     build.
# - LTO: set to 1/0 to build "--with/--without lto", otherwise the default depends
#     on the distribution.
# - NM_GIT_BUNDLE: set to a HTTP url where to fetch the nm-git-bundle-*.noarch.rpm
#     from. Set to empty to skip it. By default, it fetches the bundle from copr.
#     See "contrib/scripts/nm-copr-build-nm-git-bundle.sh" script and
#     https://copr.fedorainfracloud.org/coprs/networkmanager/NetworkManager-main/package/nm-git-bundle/

set -ex

if [[ "$DEBUG" == 1 ]]; then
    DEBUG="--with debug"
else
    DEBUG="--without debug"
fi

if [ "$LTO" = 0 ]; then
    LTO='--without lto'
elif [ "$LTO" = 1 ]; then
    LTO='--with lto'
else
    LTO=
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
        NM_GIT_BUNDLE='https://download.copr.fedorainfracloud.org/results/networkmanager/NetworkManager-main/fedora-38-x86_64/06008259-nm-git-bundle/nm-git-bundle-20230606-102458.noarch.rpm'
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
           git rev-parse --verify "refs/remotes/origin/$GIT_REF" 2>/dev/null ||
           git rev-parse --verify "$GIT_REF^{commit}" 2>/dev/null)"

git checkout -b tmp "$GIT_SHA"

./contrib/fedora/rpm/build_clean.sh -g -S -w test $DEBUG $LTO -s copr
popd

mv ./NetworkManager/contrib/fedora/rpm/latest/{SOURCES,SPECS}/* .
rm -rf ./NetworkManager
