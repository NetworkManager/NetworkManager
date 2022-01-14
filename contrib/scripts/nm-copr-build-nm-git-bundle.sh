#!/bin/bash

# create a nm-git-bundle.git bundle and a SRPM for building it
# as a package. This bundle contains the current git history
# of upstream NetworkManager.
#
# The sole purpose of this is to fetch from the bundle to safe
# downloading the entire upstream git repository of NetworkManager.
#
# This script is also used by [1] to generate the SRPM.
# [1] https://copr.fedorainfracloud.org/coprs/networkmanager/NetworkManager-main/package/nm-git-bundle/
#
# The purpose is the following. We build (many) NetworkManager packages in copr. The
# build process runs a script (contrib/scripts/nm-copr-build.sh) that fetches the git
# repository (and we cannot just do a shallow copy -- only for the stupid reason
# that the automatic version number counts all the commits in the HEAD's history).
# NetworkManager's git repository is relatively large so fetching it over and over
# is wasteful. The idea is to have a recent git-bundle of the repository, which is
# hosted close-by in the copr infrastructure. So the build script first tries to
# download the bundle to get the bulk of the git history, before doing additional
# fetches from the upstream repository.
# From time to time, a new bundle has to be generated in copr.

set -ex

if [ -z "$GIT_URL" ]; then
    GIT_URL=https://github.com/NetworkManager/NetworkManager
    #GIT_URL=https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git
fi

git clone -n "$GIT_URL"

pushd NetworkManager

REFS=(
    $(git branch -a | sed -n 's#^ *remotes/origin/\(main\|nm-1-[0-9]\+\)$#\1#p')
)

unset R
unset H
for R in "${REFS[@]}"; do
    H="$(git show-ref --verify --hash "refs/remotes/origin/$R")"
    git update-ref "refs/heads/$R" "$H"
done

git bundle create nm-git-bundle.git "${REFS[@]}"

popd

DIR="$(mktemp -d rpmbuild.XXXXXX)"

mkdir -p "$DIR/SOURCES"
mkdir -p "$DIR/SPECS"

cat <<EOF > "$DIR/SPECS/nm-git-bundle.spec"
Name: nm-git-bundle
Version: $(date '+%Y%m%d')
Release: $(date '+%H%M%S')
Summary: git-bundle of NetworkManager upstream repository

License: Public Domain
URL: https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/tree/main/contrib/fedora/rpm/nm-git-bundle.spec

%global GIT_URL 'https://github.com/NetworkManager/NetworkManager'
#global GIT_URL 'https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git'

Source0: nm-git-bundle.git


BuildArch: noarch


%description
A git-bundle of NetworkManager upstream git repository. Useful to safe
fetching the entire repository from the internet.


%install
mkdir -p %{buildroot}/usr/share/NetworkManager/
cp %{SOURCE0} %{buildroot}/usr/share/NetworkManager/


%files
/usr/share/NetworkManager/nm-git-bundle.git
EOF

mv ./NetworkManager/nm-git-bundle.git "$DIR/SOURCES/"

rpmbuild --define "_topdir $DIR"  -bs "$DIR/SPECS/nm-git-bundle.spec"

mv "$DIR/SRPMS/"nm-git-bundle-*.src.rpm .
mv "$DIR/SPECS/nm-git-bundle.spec" .
mv "$DIR/SOURCES/nm-git-bundle.git" .
rm -rf "$DIR"

