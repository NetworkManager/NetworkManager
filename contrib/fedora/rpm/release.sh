#!/bin/bash

# Script for doing NetworkManager releases.
#
# Run with --help for usage.
#
# There are 6 modes:
#
#  - "devel" : on main branch to tag a devel release (e.g. "1.25.2-dev").
#  - "rc1"   : the first release candidate on "main" branch which branches off
#              a new "nm-1-X" branch (e.g. tag "1.26-rc1" (1.25.90) and branch
#              off "nm-1-26"). On main this also bumps the version number
#              and creates a new devel release (e.g. "1.27.0-dev").
#  - "rc"    : further release candidates on RC branch (e.g. from "nm-1-26" branch
#              tag "1.26-rc2" with version number 1.25.91).
#  - "major" : on stable branch do a major release (e.g. on "nm-1-26" branch
#              release "1.26.0", followed by "1.26.1-dev").
#              You should do a "major-post" release right a "major" release.
#  - "major-post": after a "major" release, merge the release branch with main and
#              do another devel snapshot on main (e.g. do "1.27.1-dev" release).
#  - "minor" : on a stable branch do a minor release (e.g. "1.26.4" on "nm-1-26"
#              branch and bump to "1.26.5-dev").
#
# Requisites:
#
#   * You need to start with a clean working directory (git clean -fdx)
#
#   * Run in a "clean" environment, i.e. no unusual environment variables set, on a recent
#     Fedora, with suitable dependencies installed.
#
#   * First, ensure that you have ssh keys for "master.gnome.org" installed (and ssh-agent running).
#     Also, ensure you have a GPG key that you want to use for signing. Also, have gpg-agent running
#     and possibly configure `git config --get user.signingkey` for the proper key.
#
#   * Your git repository needs a remote "origin" that points to the upstream git repository.
#
#   * All your (relevant) local branches (main and nm-1-*) must be up to date with their
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
    echo "  $BASH_SOURCE [devel|rc1|rc|major|major-post|minor] [--no-test] [--no-find-backports] [--no-cleanup] [--allow-local-branches] [--no-check-gitlab] [--no-check-news]"
}

die_help() {
    print_usage
    echo
    sed -e '/^# /,/# Run with --no-test/!d' -e 's/^#\($\| \)/  /' "$BASH_SOURCE"
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
    local MAJ="$(sed -n '1,20 s/^m4_define(\[nm_major_version\], \[\([0-9]\+\)\])$/\1/p' ./configure.ac)"
    local MIN="$(sed -n '1,20 s/^m4_define(\[nm_minor_version\], \[\([0-9]\+\)\])$/\1/p' ./configure.ac)"
    local MIC="$(sed -n '1,20 s/^m4_define(\[nm_micro_version\], \[\([0-9]\+\)\])$/\1/p' ./configure.ac)"

    re='^(0|[1-9][0-9]*) (0|[1-9][0-9]*) (0|[1-9][0-9]*)$'
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

check_gitlab_pipeline() {
    local BRANCH="$1"
    local SHA="$2"
    local PIPELINE_ID

    PIPELINE_ID="$(curl --no-progress-meter "https://gitlab.freedesktop.org/api/v4/projects/411/pipelines?ref=$BRANCH&sha=$SHA&order_by=id" 2>/dev/null | jq '.[0].id')"
    if ! [[ $PIPELINE_ID =~ [0-9]+ ]] ; then
        echo "Cannot find pipeline for branch $BRANCH. Check \"https://gitlab.freedesktop.org/NetworkManager/NetworkManager/pipelines?page=1&scope=branches&ref=$BRANCH\""
        return 1
    fi

    PIPELINE_STATUSES="$(curl --no-progress-meter "https://gitlab.freedesktop.org/api/v4/projects/411/pipelines/$PIPELINE_ID/jobs" 2>/dev/null | jq '.[].status')"

    if ! echo "$PIPELINE_STATUSES" | grep -q '^"success"$' ; then
        echo "Cannot find successful jobs for branch $BRANCH. Check \"https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/pipelines/$PIPELINE_ID\""
        return 1
    fi
    if echo "$PIPELINE_STATUSES" | grep -q -v '^"success"$' ; then
        echo "Seems not all jobs for $BRANCH ran (or were successfull). Check \"https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/pipelines/$PIPELINE_ID\""
        return 1
    fi

    return 0
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

check_news() {
    local mode="$1"
    shift
    local ver_arr=("$@")

    case "$mode" in
        major|minor)
            if git grep -q 'NOT RECOMMENDED FOR PRODUCTION USE' -- ./NEWS ; then
                return 1
            fi
            ;;
        *)
            ;;
    esac
    return 0
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

BASH_SOURCE_ABSOLUTE="$(readlink -f "$BASH_SOURCE")"

test -d "$DIR" &&
cd "$DIR" &&
test -f ./contrib/fedora/rpm/build_clean.sh || die "cannot find NetworkManager base directory"

RELEASE_MODE=""
DRY_RUN=1
FIND_BACKPORTS=1
ALLOW_LOCAL_BRANCHES=0
HELP_AND_EXIT=1
CHECK_GITLAB=1
CHECK_NEWS=1
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
            # by default, the script errors out if the relevant branch (main, nm-1-Y) are not the same
            # as the remote branch on origin. You should not do a release if you have local changes
            # that differ from upstream. Set this flag to override that check.
            ALLOW_LOCAL_BRANCHES=1
            ;;
        --no-check-gitlab)
            CHECK_GITLAB=0
            ;;
        --no-check-news)
            CHECK_NEWS=0
            ;;
        --help|-h)
            die_help
            ;;
        devel|rc1|rc|major|major-post|minor)
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

grep -q "version: '${VERSION_ARR[0]}.${VERSION_ARR[1]}.${VERSION_ARR[2]}'," ./meson.build || die "meson.build does not have expected version"

TMP="$(git status --porcelain)" || die "git status failed"
test -z "$TMP" || die "git working directory is not clean (git status --porcelain)"

TMP="$(LANG=C git clean -ndx)" || die "git clean -ndx failed"
test -z "$TMP" || die "git working directory is not clean? (git clean -ndx)"

CUR_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
CUR_HEAD="$(git rev-parse HEAD)"
TMP_BRANCH=release-branch

if [ "$CUR_BRANCH" = main ]; then
    number_is_odd "${VERSION_ARR[1]}" || die "Unexpected version number on main. Should be an odd development version"
    [ "$RELEASE_MODE" = devel -o "$RELEASE_MODE" = rc1 -o "$RELEASE_MODE" = major-post ] || die "Unexpected branch name \"$CUR_BRANCH\" for \"$RELEASE_MODE\""
else
    re='^nm-[0-9]+-[0-9]+$'
    [[ "$CUR_BRANCH" =~ $re ]] || die "Unexpected current branch $CUR_BRANCH. Should be main or nm-?-??"
    if number_is_odd "${VERSION_ARR[1]}"; then
        # we are on a release candiate branch.
        [ "$RELEASE_MODE" = rc -o "$RELEASE_MODE" = major ] || die "Unexpected branch name \"$CUR_BRANCH\" for \"$RELEASE_MODE\""
        [ "$CUR_BRANCH" == "nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))" ] || die "Unexpected current branch $CUR_BRANCH. Should be nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))"
    else
        [ "$RELEASE_MODE" = minor ] || die "Unexpected branch name \"$CUR_BRANCH\" for \"$RELEASE_MODE\""
        [ "$CUR_BRANCH" == "nm-${VERSION_ARR[0]}-${VERSION_ARR[1]}" ] || die "Unexpected current branch $CUR_BRANCH. Should be nm-${VERSION_ARR[0]}-${VERSION_ARR[1]}"
    fi
fi

RC_VERSION=
RELEASE_BRANCH=
case "$RELEASE_MODE" in
    minor)
        number_is_even "${VERSION_ARR[1]}" &&
        number_is_odd  "${VERSION_ARR[2]}" || die "cannot do minor release on top of version $VERSION_STR"
        [ "$CUR_BRANCH" != main ] || die "cannot do a minor release on main"
        ;;
    devel)
        number_is_odd "${VERSION_ARR[1]}" || die "cannot do devel release on top of version $VERSION_STR"
        [ "$((${VERSION_ARR[2]} + 1))" -lt 90 ] || die "devel release must have a micro version smaller than 90 but current version is $VERSION_STR"
        [ "$CUR_BRANCH" == main ] || die "devel release can only be on main"
        ;;
    rc)
        number_is_odd "${VERSION_ARR[1]}" || die "cannot do rc release on top of version $VERSION_STR"
        [ "${VERSION_ARR[2]}" -ge 90 ] || die "rc release must have a micro version larger than ${VERSION_ARR[0]}.90 but current version is $VERSION_STR"
        RC_VERSION="$((${VERSION_ARR[2]} - 88))"
        [ "$CUR_BRANCH" == "nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))" ] || die "devel release can only be on \"nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))\" branch"
        ;;
    rc1)
        number_is_odd "${VERSION_ARR[1]}" || die "cannot do rc release on top of version $VERSION_STR"
        [ "${VERSION_ARR[2]}" -lt 90 ] || die "rc release must have a micro version smaller than ${VERSION_ARR[0]}.${VERSION_ARR[1]}.90 but current version is $VERSION_STR"
        [ "$CUR_BRANCH" == main ] || die "rc1 release can only be on main"
        RELEASE_BRANCH="nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))"
        ;;
    major)
        number_is_odd "${VERSION_ARR[1]}" || die "cannot do major release on top of version $VERSION_STR"
        [ "${VERSION_ARR[2]}" -ge 90 ] || die "parent version for major release must have a micro version larger than ${VERSION_ARR[0]}.90 but current version is $VERSION_STR"
        [ "$CUR_BRANCH" == "nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))" ] || die "major release can only be on \"nm-${VERSION_ARR[0]}-$((${VERSION_ARR[1]} + 1))\" branch"
        ;;
    major-post)
        number_is_odd "${VERSION_ARR[1]}" || die "cannot do major-post release on top of version $VERSION_STR"
        [ "$((${VERSION_ARR[2]} + 1))" -lt 90 ] || die "major-post release must have a micro version smaller than 90 but current version is $VERSION_STR"
        [ "$CUR_BRANCH" == main ] || die "major-post release can only be on main"
        ;;
    *)
        die "Release mode $RELEASE_MODE not yet implemented"
        ;;
esac

git fetch "$ORIGIN" || die "git fetch failed"

if [ "$ALLOW_LOCAL_BRANCHES" != 1 ]; then
    git_same_ref "$CUR_BRANCH" "refs/heads/$CUR_BRANCH" || die "Current branch $CUR_BRANCH is not a branch??"
    git_same_ref "$CUR_BRANCH" "refs/remotes/$ORIGIN/$CUR_BRANCH" || die "Current branch $CUR_BRANCH seems not up to date with refs/remotes/$ORIGIN/$CUR_BRANCH. Git pull or --allow-local-branches?"
fi

NEWER_BRANCHES=()
if [ "$CUR_BRANCH" != main ]; then
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
            git_same_ref "$b" "refs/remotes/$ORIGIN/$b" || die "branch $b seems not up to date with refs/remotes/$ORIGIN/$b. Git pull or --allow-local-branches?"
        fi
        NEWER_BRANCHES+=("refs/heads/$b")
    done
    b=main
    if [ "$ALLOW_LOCAL_BRANCHES" != 1 ]; then
        git_same_ref "$b" "refs/heads/$b" || die "branch $b is not a branch??"
        git_same_ref "$b" "refs/remotes/$ORIGIN/$b" || die "branch $b seems not up to date with refs/remotes/$ORIGIN/$b. Git pull or --allow-local-branches?"
    fi
fi

if [ -n "$RELEASE_BRANCH" ]; then
    git show-ref --verify --quiet "refs/remotes/$ORIGIN/$RELEASE_BRANCH" && die "release branch refs/remotes/$ORIGIN/$RELEASE_BRANCH unexpectedly exists already"
    git show-ref --verify --quiet "refs/heads/$RELEASE_BRANCH" && die "release branch refs/heads/$RELEASE_BRANCH unexpectedly exists already"
fi

if [ "$ALLOW_LOCAL_BRANCHES" != 1 ]; then
    cmp <(git show origin/main:contrib/fedora/rpm/release.sh) "$BASH_SOURCE_ABSOLUTE" || die "$BASH_SOURCE is not identical to \`git show origin/main:contrib/fedora/rpm/release.sh\`"
fi

if ! check_news "$RELEASE_MODE" "@{VERSION_ARR[@]}" ; then
    if [ "$CHECK_NEWS" == 1 ]; then
        die "NEWS file needs update to mention stable release (skip check with --no-check-news)"
    fi
    echo "WARNING: NEWS file needs update to mention stable release (test skipped with --no-check-news)"
fi

if [ $FIND_BACKPORTS = 1 ]; then
    git show "$ORIGIN/main:contrib/scripts/find-backports" > ./.git/nm-find-backports \
    && chmod +x ./.git/nm-find-backports \
    || die "cannot get contrib/scripts/find-backports"

    TMP="$(./.git/nm-find-backports "$CUR_BRANCH" main "${NEWER_BRANCHES[@]}" 2>/dev/null)" || die "nm-find-backports failed"
    test -z "$TMP" || die "nm-find-backports returned patches that need to be backported (ignore with --no-find-backports): ./.git/nm-find-backports \"$CUR_BRANCH\" main ${NEWER_BRANCHES[@]}"
fi

if [ $CHECK_GITLAB = 1 ]; then
    if ! check_gitlab_pipeline "$CUR_BRANCH" "$CUR_HEAD" ; then
        echo "Check the pipelines for branch \"$CUR_BRANCH\" at https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/pipelines/"
        die "It seems not all gitlab-ci jobs were running/succeeding. Skip this check with --no-check-gitlab"
    fi
fi

BRANCHES=()
BUILD_TAG=

CLEANUP_CHECKOUT_BRANCH="$CUR_BRANCH"

git checkout -B "$TMP_BRANCH"
CLEANUP_REFS+=("refs/heads/$TMP_BRANCH")

case "$RELEASE_MODE" in
    minor)
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 1))
        git commit -m "release: bump version to ${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))" -a || die "failed to commit release"
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 2))
        git commit -m "release: bump version to ${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 2)) (development)" -a || die "failed to commit devel version bump"

        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))"
        git tag -s -a -m "Tag $b" "$b" HEAD~ || die "failed to tag release"
        BRANCHES+=("$b")
        CLEANUP_REFS+=("refs/tags/$b")
        BUILD_TAG="$b"
        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 2))"
        git tag -s -a -m "Tag $b (development)" "$b-dev" HEAD || die "failed to tag devel version"
        BRANCHES+=("$b-dev")
        CLEANUP_REFS+=("refs/tags/$b-dev")
        TAR_VERSION="$BUILD_TAG"
        ;;
    devel)
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 1))
        git commit -m "release: bump version to ${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1)) (development)" -a || die "failed to commit devel version bump"

        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))"
        git tag -s -a -m "Tag $b (development)" "$b-dev" HEAD || die "failed to tag release"
        BRANCHES+=("$b-dev")
        CLEANUP_REFS+=("refs/tags/$b-dev")
        BUILD_TAG="$b-dev"
        TAR_VERSION="$b"
        ;;
    rc)
        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$(("${VERSION_ARR[2]}" + 1))"
        t="${VERSION_ARR[0]}.$(("${VERSION_ARR[1]}" + 1))-rc$RC_VERSION"
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" $(("${VERSION_ARR[2]}" + 1))
        git commit -m "release: bump version to $b ($t) (development)" -a || die "failed to commit rc version bump"

        git tag -s -a -m "Tag $b ($t) (development)" "$t" HEAD || die "failed to tag release"
        BRANCHES+=("$t")
        CLEANUP_REFS+=("refs/tags/$t")
        BUILD_TAG="$t"
        TAR_VERSION="$b"
        ;;
    rc1)
        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" 90
        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.90"
        t="${VERSION_ARR[0]}.$(("${VERSION_ARR[1]}" + 1))-rc1"
        git commit -m "release: bump version to $b ($t)" -a || die "failed to commit rc1 version bump"

        git tag -s -a -m "Tag $b ($t) (development)" "$t" HEAD || die "failed to tag release $t"
        BRANCHES+=("$t")
        CLEANUP_REFS+=("refs/tags/$t")
        BUILD_TAG="$t"
        TAR_VERSION="$b"
        ;;
    major)
        b="${VERSION_ARR[0]}.$((${VERSION_ARR[1]} + 1)).0"
        b2="${VERSION_ARR[0]}.$((${VERSION_ARR[1]} + 1)).1"

        set_version_number "${VERSION_ARR[0]}" "$((${VERSION_ARR[1]} + 1))" 0
        git commit -m "release: bump version to $b" -a || die "failed to commit major version bump"
        git tag -s -a -m "Tag $b" "$b" HEAD || die "failed to tag release"
        BRANCHES+=("$b")
        CLEANUP_REFS+=("refs/tags/$b")

        set_version_number "${VERSION_ARR[0]}" "$((${VERSION_ARR[1]} + 1))" 1
        git commit -m "release: bump version to $b2 (development)" -a || die "failed to commit another bump after major version bump"
        git tag -s -a -m "Tag $b (development)" "$b2-dev" HEAD || die "failed to tag release"
        BRANCHES+=("$b2-dev")
        CLEANUP_REFS+=("refs/tags/$b2-dev")

        BUILD_TAG="$b"
        TAR_VERSION="$b"
        ;;
    major-post)
        # We create a merge commit with the content of current "main", with two
        # parent commits $THE_RELEASE and "main". But we want that the first parent
        # is the release, so that `git log --first-parent` follows the path with the
        # release candidates, and not the devel part during that time. Hence this
        # switcheroo here.
        git checkout -B "$TMP_BRANCH" "${VERSION_ARR[0]}.$((${VERSION_ARR[1]} - 1)).0" || die "merge0"
        git merge -Xours --commit -m tmp main || die "merge1"
        git rm --cached -r . || die "merge2"
        git checkout main -- . || die "merge3"
        b="${VERSION_ARR[0]}.${VERSION_ARR[1]}.$((${VERSION_ARR[2]} + 1))"
        git commit --amend -m tmp -a || die "failed to commit major version bump"
        test x = "x$(git diff main HEAD)" || die "there is a diff after merge!"

        set_version_number "${VERSION_ARR[0]}" "${VERSION_ARR[1]}" "$((${VERSION_ARR[2]} + 1))"
        git commit --amend -m "release: bump version to $b (development)" -a || die "failed to commit major version bump"
        git tag -s -a -m "Tag $b (development)" "$b-dev" HEAD || die "failed to tag release"
        BRANCHES+=("$b-dev")
        CLEANUP_REFS+=("refs/tags/$b-dev")
        BUILD_TAG="$b-dev"
        TAR_VERSION="$b"
        ;;
    *)
        die "Release mode $RELEASE_MODE not yet implemented"
        ;;
esac

build_tag() {
    git checkout "$BUILD_TAG" || die "failed to checkout $BUILD_TAG"

    ./contrib/fedora/rpm/build_clean.sh -r || die "build release failed"

    test -f "./$RELEASE_FILE" \
    || die "release file \"./$RELEASE_FILE\" not found"

    cp "./$RELEASE_FILE" /tmp/ || die "failed to copy release tarball to /tmp"

    if test -f "./$RELEASE_FILE.sig" ; then
        cp "./$RELEASE_FILE.sig" /tmp/ || die "failed to copy signature for tarball to /tmp"
    fi

    git clean -fdx
}

RELEASE_FILES=()
if [ -n "$BUILD_TAG" ]; then
    RELEASE_FILE="NetworkManager-$TAR_VERSION.tar.xz"
    RELEASE_FILES+=("$RELEASE_FILE")
    build_tag
fi
git checkout -B "$CUR_BRANCH" "$TMP_BRANCH" || die "cannot checkout $CUR_BRANCH"

BRANCHES+=( "$CUR_BRANCH" )

if [ "$RELEASE_MODE" = rc1 ]; then
    git branch "$RELEASE_BRANCH" "$TMP_BRANCH" || die "cannot checkout $CUR_BRANCH"
    BRANCHES+=( "$RELEASE_BRANCH" )
    CLEANUP_REFS+=( "refs/heads/$RELEASE_BRANCH" )
fi

if [ "$RELEASE_MODE" = rc1 ]; then
    git checkout "$TMP_BRANCH"
    b="${VERSION_ARR[0]}.$((${VERSION_ARR[1]} + 2)).0"
    set_version_number "${VERSION_ARR[0]}" "$((${VERSION_ARR[1]} + 2))" 0
    git commit -m "release: bump version to $b (development)" -a || die "failed to commit devel version bump"
    git tag -s -a -m "Tag $b (development)" "$b-dev" HEAD || die "failed to tag release"
    BRANCHES+=("$b-dev")
    CLEANUP_REFS+=("refs/tags/$b-dev")
    BUILD_TAG="$b-dev"
    TAR_VERSION="$b"
    RELEASE_FILE="NetworkManager-$TAR_VERSION.tar.xz"
    RELEASE_FILES+=("$RELEASE_FILE")
    build_tag
    git checkout -B "$CUR_BRANCH" "$TMP_BRANCH" || die "cannot checkout $CUR_BRANCH"
fi

if ! [ "$DRY_RUN" = 0 ]; then
    ssh master.gnome.org true || die "failed to \`ssh master.gnome.org\`"
fi

for r in "${RELEASE_FILES[@]}"; do
    do_command rsync -va --append-verify -P "/tmp/$r" master.gnome.org: || die "failed to rsync \"/tmp/$r\""
done

do_command git push "$ORIGIN" "${BRANCHES[@]}" || die "failed to to push branches ${BRANCHES[@]} to $ORIGIN"

for r in "${RELEASE_FILES[@]}"; do
    do_command ssh master.gnome.org ftpadmin install --unattended "$r" || die "ftpadmin install failed"
done

CLEANUP_CHECKOUT_BRANCH=
if [ "$DRY_RUN" = 0 ]; then
    CLEANUP_REFS=()
    git branch -D "$TMP_BRANCH"
else
    H="$(git rev-parse "$CUR_BRANCH")"
    git checkout -B "$CUR_BRANCH" "$CUR_HEAD" || die "cannot reset $CUR_BRANCH to $CUR_HEAD"
    echo "delete reference. Restore with $(echo_color 36 -n git checkout -B "\"$CUR_BRANCH\"" "$H")"
fi
