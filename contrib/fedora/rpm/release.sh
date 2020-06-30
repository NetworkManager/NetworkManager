#!/bin/bash

# Script for doing NetworkManager releases.
#
# Run with --help for usage.
#
# There are 5 modes:
#
#  - "devel" : on master branch to tag "1.25.2-dev"
#  - "rc1"   : the first release candidate on "master" branch which branches off
#              "nm-1-26" branch. The tag is "1.26-rc1" with version number 1.25.90.
#  - "rc"    : further release candidates on RC branch "nm-1-26". For example
#              "1.26-rc2" with version number 1.25.91.
#  - "major" : on stable branch nm-1-26 to release 1.26.0. This also merged
#              the release with master branch and does a devel tag like "1.27.2-dev"
#  - "minor" : on a stable branch nm-1-26 to do minor release 1.26.4 and bump
#              to "1.26.5-dev".
#
# Requisites:
#
#   * You need to start with a clean working directory (git clean -fdx)
#
#   * Run in a "clean" environment, no unusual environment variables set.
#
#   * First, ensure that you have ssh keys for master.gnome.org installed (and ssh-agent running)
#     Also, ensure you have a GPG key that you want to use for signing. Also, have gpg-agent running
#     and possibly configure `git config --get user.signingkey` for the proper key.
#
#   * Your git repository needs a remote "origin" that points to the upstream git repository.
#
#   * All your (relevant) local branches (master and nm-1-*) must be up to date with their
#     remote tracking branches for origin.
#
# Run with --no-test to do the actual release.

die() {
    echo -n "FAIL: "
    echo_color 31 "$@"
    exit 1
}

echo_color() {
    local color="$1"
    shift
    echo -e -n "\033[0;${color}m"
    echo "$@"
    echo -e -n '\033[0m'
}

print_usage() {
    echo "Usage:"
    echo "  $BASH_SOURCE [devel|rc1|rc|major|minor] [--no-test] [--no-find-backports] [--no-cleanup] [--allow-local-branches]"
}

die_help() {
    print_usage
    exit 0
}

die_usage() {
    echo -n "FAIL: "
    echo_color 31 "$@"
    echo
    print_usage
    exit 1
}

do_command() {
    local color=36
    if [ "$DRY_RUN" = 0 ]; then
        color=31
    fi
    echo -n "COMMAND: "
    echo_color $color -n "$@"
    echo
    if [ "$DRY_RUN" = 0 ]; then
        "$@"
    fi
}

parse_version() {
    local MAJ="$(sed -n '1,20 s/^m4_define(\[nm_major_version\], \[\([0-9]\+\)\])$/\1/p' configure.ac)"
    local MIN="$(sed -n '1,20 s/^m4_define(\[nm_minor_version\], \[\([0-9]\+\)\])$/\1/p' configure.ac)"
    local MIC="$(sed -n '1,20 s/^m4_define(\[nm_micro_version\], \[\([0-9]\+\)\])$/\1/p' configure.ac)"

    re='^[0-9]+ [0-9]+ [0-9]+$'
    [[ "$MAJ $MIN $MIC" =~ $re ]] || return 1
    echo "$MAJ $MIN $MIC"
}

number_is_even() {
    local re='^[0-9]*[02468]$'
    [[ "$1" =~ $re ]]
}

number_is_odd() {
    local re='^[0-9]*[13579]$'
    [[ "$1" =~ $re ]]
}

git_same_ref() {
    local a="$(git rev-parse "$1" 2>/dev/null)" || return 1
    local b="$(git rev-parse "$2" 2>/dev/null)" || return 1
    [ "$a" = "$b" ]
}

set_version_number_autotools() {
    sed -i \
        -e '1,20 s/^m4_define(\[nm_major_version\], \[\([0-9]\+\)\])$/m4_define([nm_major_version], ['"$1"'])/' \
        -e '1,20 s/^m4_define(\[nm_minor_version\], \[\([0-9]\+\)\])$/m4_define([nm_minor_version], ['"$2"'])/' \
        -e '1,20 s/^m4_define(\[nm_micro_version\], \[\([0-9]\+\)\])$/m4_define([nm_micro_version], ['"$3"'])/' \
        ./configure.ac
}

set_version_number_meson() {
    sed -i \
        -e '1,20 s/^\( *version: *'\''\)[0-9]\+\.[0-9]\+\.[0-9]\+\('\'',\)$/\1'"$1.$2.$3"'\2/' \
        meson.build
}

set_version_number() {
    set_version_number_autotools "$@" &&
    set_version_number_meson "$@"
}

DO_CLEANUP=1
CLEANUP_CHECKOUT_BRANCH=
CLEANUP_REFS=()
cleanup() {
    if [ $DO_CLEANUP = 1 ]; then
        [ -n "$CLEANUP_CHECKOUT_BRANCH" ] && git checkout -f "$CLEANUP_CHECKOUT_BRANCH"
        for c in "${CLEANUP_REFS[@]}"; do
            echo "delete reference. Restore with $(echo_color 36 -n git update-ref \"$c\" $(git rev-parse "$c"))"
            git update-ref -d "$c"
        done
    fi
}

trap cleanup EXIT

DIR="$(git rev-parse --show-toplevel)"

ORIGIN=origin

test -d "$DIR" &&
cd "$DIR" &&
test -f ./src/NetworkManagerUtils.h &&
test -f ./contrib/fedora/rpm/build_clean.sh || die "cannot find NetworkManager base directory"

RELEASE_MODE=""
DRY_RUN=1
FIND_BACKPORTS=1
ALLOW_LOCAL_BRANCHES=0
HELP_AND_EXIT=1
while [ "$#" -ge 1 ]; do
    A="$1"
    shift
    HELP_AND_EXIT=0
    case "$A" in
        --no-test)
            DRY_RUN=0
            ;;
        --no-find-backports)
            FIND_BACKPORTS=0
            ;;
        --no-cleanup)
            DO_CLEANUP=0
            ;;
        --allow-local-branches)
            # by default, the script errors out if the relevant branch (master, nm-1-Y) are not the same
            # as the remote branch on origin. You should not do a release if you have local changes
            # that differ from upstream. Set this flag to override that check.
            ALLOW_LOCAL_BRANCHES=1
            ;;
        --help|-h)
            die_help
            ;;
        devel|rc1|rc|major|minor)
            [ -z "$RELEASE_MODE" ] || die_usage "duplicate release-mode"
            RELEASE_MODE="$A"
            ;;
        *)
            die_usage "unknown argument \"$A\""
            ;;
    esac
done
[ "$HELP_AND_EXIT" = 1 ] && die_help

[ -n "$RELEASE_MODE" ] || die_usage "specify the desired release mode"

VERSION_ARR=( $(parse_version) ) || die "cannot detect NetworkManager version"
VERSION_STR="$(IFS=.; echo "${VERSION_ARR[*]}")"

echo "Current version before release: $VERSION_STR (do \"$RELEASE_MODE\" release)"

TMP="$(git status --porcelain)" || die "git status failed"
test -z "$TMP" || die "git working directory is not clean (git status --porcelain)"

TMP="$(LANG=C git clean -ndx)" || die "git clean -ndx failed"
test -z "$TMP" || die "git working directory is not clean? (git clean -ndx)"

CUR_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
TMP_BRANCH=release-branch

if [ "$CUR_BRANCH" = master ]; then
    number_is_odd "${VERSION_ARR[1]}" || die "Unexpected version number on master. Should be an odd development version"
else
    re='^nm-[0-9]+-[0-9]+$'
    [[ "$CUR_BRANCH" =~ $re ]] || die "Unexpected current branch $CUR_BRANCH. Should be master or nm-?-??"
    if number_is_odd "${VERSION_ARR[1]}"; then
        # we are on a release candiate branch.
        [ "$RELEASE_MODE" = rc ] || "Unexpected branch name \"$CUR_BRANCH\" for \"$RELEASE_MODE\""
        [ "$CUR_BRANCH" == "nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))" ] || die "Unexpected current branch $CUR_BRANCH. Should be nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))"
    else
        [ "$CUR_BRANCH" == "nm-${VERSION_ARR[0]}-${VERSION_ARR[1]}" ] || die "Unexpected current branch $CUR_BRANCH. Should be nm-${VERSION_ARR[0]}-${VERSION_ARR[1]}"
    fi
fi

RC_VERSION=
case "$RELEASE_MODE" in
    minor)
        number_is_even "${VERSION_ARR[1]}" &&
        number_is_odd  "${VERSION_ARR[2]}" || die "cannot do minor release on top of version $VERSION_STR"
        [ "$CUR_BRANCH" != master ] || die "cannot do a minor release on master"
        ;;
    devel|rc)
        number_is_odd "${VERSION_ARR[1]}" || die "cannot do devel release on top of version $VERSION_STR"
        if [ "$RELEASE_MODE" = devel ]; then
            [ "$((${VERSION_ARR[2]} + 1))" -lt 90 ] || die "devel release must have a micro version smaller than 90 but current version is $VERSION_STR"
            [ "$CUR_BRANCH" == master ] || die "devel release can only be on master"
        else
            [ "${VERSION_ARR[2]}" -ge 90 ] || die "rc release must have a micro version larger than ${VERSION_ARR[0]}.90 but current version is $VERSION_STR"
            RC_VERSION="$((${VERSION_ARR[2]} - 88))"
            [ "$CUR_BRANCH" == "nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))" ] || die "devel release can only be on \"nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))\" branch"
        fi
        ;;
    *)
        die "Release mode $RELEASE_MODE not yet implemented"
        ;;
esac

git fetch || die "git fetch failed"

if [ "$ALLOW_LOCAL_BRANCHES" != 1 ]; then
    git_same_ref "$CUR_BRANCH" "refs/heads/$CUR_BRANCH" || die "Current branch $CUR_BRANCH is not a branch??"
    git_same_ref "$CUR_BRANCH" "refs/remotes/$ORIGIN/$CUR_BRANCH" || die "Current branch $CUR_BRANCH seems not up to date with refs/remotes/$ORIGIN/$CUR_BRANCH. Git pull?"
fi

NEWER_BRANCHES=()
if [ "$CUR_BRANCH" != master ]; then
    i="${VERSION_ARR[1]}"
    while : ; do
        i=$((i + 2))
        b="nm-${VERSION_ARR[0]}-$i"
        if ! git show-ref --verify --quiet "refs/remotes/$ORIGIN/$b"; then
            git show-ref --verify --quiet "refs/heads/$b" && die "unexpectedly branch $b exists"
            break
        fi
        if [ "$ALLOW_LOCAL_BRANCHES" != 1 ]; then
            git_same_ref "$b" "refs/heads/$b" || die "branch $b is not a branch??"
            git_same_ref "$b" "refs/remotes/$ORIGIN/$b" || die "branch $b seems not up to date with refs/remotes/$ORIGIN/$b. Git pull?"
        fi
        NEWER_BRANCHES+=("refs/heads/$b")
    done
    b=master
    if [ "$ALLOW_LOCAL_BRANCHES" != 1 ]; then
        git_same_ref "$b" "refs/heads/$b" || die "branch $b is not a branch??"
        git_same_ref "$b" "refs/remotes/$ORIGIN/$b" || die "branch $b seems not up to date with refs/remotes/$ORIGIN/$b. Git pull?"
    fi
fi

if [ "$ALLOW_LOCAL_BRANCHES" != 1 ]; then
    cmp <(git show origin/master:contrib/fedora/rpm/release.sh) "$BASH_SOURCE" || die "$BASH_SOURCE is not identical to \`git show origin/master:contrib/fedora/rpm/release.sh\`"
fi

if [ $FIND_BACKPORTS = 1 ]; then
    git show "$ORIGIN/automation:contrib/rh-utils/find-backports.sh" > ./.git/nm-find-backports.sh \
    && chmod +x ./.git/nm-find-backports.sh \
    || die "cannot get contrib/rh-utils/find-backports.sh"

    TMP="$(./.git/nm-find-backports.sh "$(git merge-base master HEAD)" "$CUR_BRANCH" master "${NEWER_BRANCHES[@]}")" || die "nm-find-backports failed"
    test -z "$TMP" || die "nm-find-backports returned patches that need to be backported: ./.git/nm-find-backports.sh \"\$(git merge-base master HEAD)\" \"$CUR_BRANCH\" master ${NEWER_BRANCHES[@]}"
fi

TAGS=()
BUILD_TAG=

CLEANUP_CHECKOUT_BRANCH="$CUR_BRANCH"

CLEANUP_REFS+=("$TMP_BRANCH")

case "$RELEASE_MODE" in
    minor)
        git checkout -B "$TMP_BRANCH"
        CLEANUP_REFS+=("refs/heads/$TMP_BRANCH")
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 1))
        git commit -m "release: bump version to ${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))" -a || die "failed to commit release"
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 2))
        git commit -m "release: bump version to ${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 2)) (development)" -a || die "failed to commit devel version bump"

        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))"
        git tag -s -a -m "Tag $b" "$b" HEAD~ || die "failed to tag release"
        TAGS+=("$b")
        CLEANUP_REFS+=("refs/tags/$b")
        BUILD_TAG="$b"
        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 2))"
        git tag -s -a -m "Tag $b (development)" "$b-dev" HEAD || die "failed to tag devel version"
        TAGS+=("$b-dev")
        CLEANUP_REFS+=("refs/tags/$b-dev")
        TAR_VERSION="$BUILD_TAG"
        ;;
    devel)
        git checkout -B "$TMP_BRANCH"
        CLEANUP_REFS+=("refs/heads/$TMP_BRANCH")
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 1))
        git commit -m "release: bump version to ${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1)) (development)" -a || die "failed to commit devel version bump"

        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))"
        git tag -s -a -m "Tag $b (development)" "$b-dev" HEAD || die "failed to tag release"
        TAGS+=("$b-dev")
        CLEANUP_REFS+=("refs/tags/$b-dev")
        BUILD_TAG="$b-dev"
        TAR_VERSION="$b"
        ;;
    rc)
        git checkout -B "$TMP_BRANCH"
        CLEANUP_REFS+=("refs/heads/$TMP_BRANCH")
        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))"
        t="${VERSION_ARR[0]}.$(("${VERSION_ARR[1]}" + 1))-rc$RC_VERSION"
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 1))
        git commit -m "release: bump version to $b ($t) (development)" -a || die "failed to commit rc version bump"

        git tag -s -a -m "Tag $b ($t) (development)" "$t" HEAD || die "failed to tag release"
        TAGS+=("$t")
        CLEANUP_REFS+=("refs/tags/$t")
        BUILD_TAG="$t"
        TAR_VERSION="$b"
        ;;
    *)
        die "Release mode $RELEASE_MODE not yet implemented"
        ;;
esac

RELEASE_FILE=

if [ -n "$BUILD_TAG" ]; then
    git checkout "$BUILD_TAG" || die "failed to checkout $BUILD_TAG"

    ./contrib/fedora/rpm/build_clean.sh -r || die "build release failed"

    RELEASE_FILE="NetworkManager-$TAR_VERSION.tar.xz"

    test -f "./$RELEASE_FILE" \
    && test -f "./$RELEASE_FILE.sig" \
    || die "release file \"./$RELEASE_FILE\" not found"

    cp "./$RELEASE_FILE" "./$RELEASE_FILE.sig" /tmp || die "failed to copy release tarball to /tmp"

    git clean -fdx
fi

if [ -n "$RELEASE_FILE" ]; then
    do_command rsync -va --append-verify -P "/tmp/$RELEASE_FILE" master.gnome.org: || die "failed to rsync \"/tmp/$RELEASE_FILE\""
    do_command ssh master.gnome.org ftpadmin install --unattended "$RELEASE_FILE" || die "ftpadmin install failed"
fi

git checkout -B "$CUR_BRANCH" "$TMP_BRANCH" || die "cannot checkout $CUR_BRANCH"

do_command git push "$ORIGIN" "${TAGS[@]}" "$CUR_BRANCH"

if [ "$DRY_RUN" = 0 ]; then
    CLEANUP_REFS=()
    CLEANUP_CHECKOUT_BRANCH=
fi
