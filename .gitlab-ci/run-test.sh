#!/bin/bash

set -ex

export PAGER=cat
export OMP_NUM_THREADS=1

IS_FEDORA=0
IS_CENTOS=0
IS_ALPINE=0
grep -q '^NAME=.*\(CentOS\)' /etc/os-release && IS_CENTOS=1
grep -q '^NAME=.*\(Fedora\)' /etc/os-release && IS_FEDORA=1
grep -q '^NAME=.*\(Alpine\)' /etc/os-release && IS_ALPINE=1

IS_CENTOS_7=0
if [ $IS_CENTOS = 1 ]; then
    if grep -q '^VERSION_ID=.*\<7\>' /etc/os-release ; then
        IS_CENTOS_7=1
    fi
fi

do_clean() {
    git clean -fdx

    git status
    git diff --exit-code
}

ARTIFACT_DIR=/tmp/nm-artifact
rm -rf "$ARTIFACT_DIR"
mkdir -p "$ARTIFACT_DIR"

uname -a
! command -v locale &>/dev/null || locale -a
meson --version

! command -v dpkg &>/dev/null || dpkg -l
! command -v yum  &>/dev/null || yum list installed
! command -v apk  &>/dev/null || apk -v info

# We have a unit test that check that `ci-fairy generate-template`
# is equal to our .gitlab-ci.yml file. However, on gitlab-ci we
# also have a dedicate test for the same thing. We don't need
# to run that test as part of the build. Disable it.
export NMTST_SKIP_CHECK_GITLAB_CI=1

check_run() {
    local test_no="$1"

    # Usually, we run the build several times. However, for testing
    # the build script manually, it can be useful to explicitly select
    # one step to run. For example, if step 3 is known to fail, you
    # can still manually run step 4 by setting NM_TEST_SELECT_RUN=4.

    test -z "$NM_TEST_SELECT_RUN" -o "$NM_TEST_SELECT_RUN" = "$test_no"
}


check_run_clean() {
    if ! check_run "$1" ; then
        return 1
    fi
    do_clean
    return 0
}

if check_run_clean 1 ; then
    BUILD_TYPE=autotools CC=gcc WITH_DOCS=1 WITH_VALGRIND=1 contrib/scripts/nm-ci-run.sh
    mv build/INST/share/gtk-doc/html "$ARTIFACT_DIR/docs-html"
fi

check_run_clean 2 && BUILD_TYPE=meson     CC=gcc   WITH_DOCS=1 WITH_VALGRIND=1 contrib/scripts/nm-ci-run.sh
check_run_clean 3 && BUILD_TYPE=autotools CC=clang WITH_DOCS=0                 contrib/scripts/nm-ci-run.sh
check_run_clean 4 && BUILD_TYPE=meson     CC=clang WITH_DOCS=0                 contrib/scripts/nm-ci-run.sh

check_run_clean 5 && test $IS_CENTOS_7 = 1 && PYTHON=python2 BUILD_TYPE=autotools CC=gcc WITH_DOCS=1 contrib/scripts/nm-ci-run.sh

check_run_clean 6 && test $IS_FEDORA = 1 -o $IS_CENTOS = 1 && ./contrib/fedora/rpm/build_clean.sh -g -w crypto_gnutls -w debug -w iwd -w test -W meson
check_run_clean 7 && test $IS_FEDORA = 1                   && ./contrib/fedora/rpm/build_clean.sh -g -w crypto_gnutls -w debug -w iwd -w test -w meson

if check_run_clean 8 && [ "$NM_BUILD_TARBALL" = 1 ]; then
    SIGN_SOURCE=0 ./contrib/fedora/rpm/build_clean.sh -r
    mv ./NetworkManager-1*.tar.xz "$ARTIFACT_DIR/"
    mv ./contrib/fedora/rpm/latest/SRPMS/NetworkManager-1*.src.rpm "$ARTIFACT_DIR/"
    do_clean
fi

###############################################################################

test_subtree() {
    local d="$1"
    local cc="$2"

    if meson --version | grep -q '^0\.[0-5][0-9]\.' ; then
        # These subprojects require a newer meson than NetworkManager. Skip the test.
        return 0
    fi

    do_clean
    pushd ./src/$d

    ARGS=()
    if [ "$d" = n-acd ]; then
        ARGS+=('-Debpf=false')
    fi

    CC="$cc" CFLAGS="-Werror -Wall" meson build "${ARGS[@]}"
    ninja -v -C build test

    popd
}

if check_run_clean 10; then
    for d in c-list c-rbtree c-siphash c-stdaux n-acd n-dhcp4 ; do
        for cc in gcc clang; do
            test_subtree "$d" "$cc"
        done
    done
fi

###############################################################################

if [ -z "$NM_TEST_SELECT_RUN" ] ; then
    do_clean
    if [ "$NM_BUILD_TARBALL" = 1 ]; then
        if check_run 1 ; then
            mv "$ARTIFACT_DIR/docs-html/" ./
        fi
        if check_run 8 ; then
            mv \
               "$ARTIFACT_DIR"/NetworkManager-1*.tar.xz \
               "$ARTIFACT_DIR"/NetworkManager-1*.src.rpm \
               ./
        fi
    fi
fi

echo "BUILD SUCCESSFUL!!"
