#!/bin/bash

set -ex

IS_FEDORA=0
IS_CENTOS=0
IS_ALPINE=0
grep -q '^NAME=.*\(CentOS\)' /etc/os-release && IS_CENTOS=1
grep -q '^NAME=.*\(Fedora\)' /etc/os-release && IS_FEDORA=1
grep -q '^NAME=.*\(Alpine\)' /etc/os-release && IS_ALPINE=1

do_clean() {
    git clean -fdx
}

uname -a
! command -v locale &>/dev/null || locale -a
env
meson --version

! command -v dpkg &>/dev/null || dpkg -l
! command -v yum  &>/dev/null || yum list installed
! command -v apk  &>/dev/null || apk -v info

# The formatting depends on the version of python black.
# We have a dedicated test that checks our formatting, which
# uses the right version. We should disable the check during
# `make check`.
export NMTST_SKIP_PYTHON_BLACK=1

# We have a unit test that check that `ci-fairy generate-template`
# is equal to our .gitlab-ci.yml file. However, on gitlab-ci we
# also have a dedicate test for the same thing. We don't need
# to run that test as part of the build. Disable it.
export NMTST_SKIP_CHECK_GITLAB_CI=1

do_clean; BUILD_TYPE=autotools CC=gcc   WITH_DOCS=1 WITH_VALGRIND=1 contrib/scripts/nm-ci-run.sh
rm -rf /tmp/nm-docs-html;
mv build/INST/share/gtk-doc/html /tmp/nm-docs-html
do_clean; BUILD_TYPE=meson     CC=gcc   WITH_DOCS=1 WITH_VALGRIND=1 contrib/scripts/nm-ci-run.sh
do_clean; BUILD_TYPE=autotools CC=clang WITH_DOCS=0                 contrib/scripts/nm-ci-run.sh
do_clean; BUILD_TYPE=meson     CC=clang WITH_DOCS=0                 contrib/scripts/nm-ci-run.sh

do_clean; test $IS_FEDORA = 1 -o $IS_CENTOS = 1 && ./contrib/fedora/rpm/build_clean.sh -g -w crypto_gnutls -w debug -w iwd -w test -W meson
do_clean; test $IS_FEDORA = 1                   && ./contrib/fedora/rpm/build_clean.sh -g -w crypto_gnutls -w debug -w iwd -w test -w meson

do_clean
if [ "$NM_BUILD_TARBALL" = 1 ]; then
    SIGN_SOURCE=0 ./contrib/fedora/rpm/build_clean.sh -r
    mv ./NetworkManager-1*.tar.xz /tmp/
    mv ./contrib/fedora/rpm/latest/SRPMS/NetworkManager-1*.src.rpm /tmp/
    do_clean
    mv /tmp/nm-docs-html ./docs-html
    mv /tmp/NetworkManager-1*.tar.xz /tmp/NetworkManager-1*.src.rpm ./
fi

echo "BUILD SUCCESSFUL!!"
