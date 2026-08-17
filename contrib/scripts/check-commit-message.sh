#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Called from the "commit-msg" hook in .pre-commit-config.yaml, which passes
# the message file, and from the "check-tree" gitlab-ci job.
#
# The message has to be read from git, not from "git format-patch" output like
# checkpatch.pl does: format-patch appends a "Signed-off-by:" trailer of its
# own when the contributor has "format.signOff" set.

set -e

die() {
    printf '%s\n' "$@" >&2
    exit 1
}

usage() {
    printf 'Usage: %s <commit-message-file>\n' "$(basename "$0")"
    printf '       %s --ci\n' "$(basename "$0")"
    printf '       %s --range <git-range>\n' "$(basename "$0")"
    printf '\n'
    printf 'Check commit messages against the rules from CONTRIBUTING.md.\n'
}

check_trailer() {
    local source="$1"
    local message="$2"
    local trailer="$3"
    local reason="$4"
    local hit

    hit="$(printf '%s\n' "$message" | grep -i "^$trailer:")" || return 0

    printf '%s: do not use "%s:" lines, %s (see CONTRIBUTING.md)\n' "$source" "$trailer" "$reason" >&2
    sed 's/^/> /' <<<"$hit" >&2
    printf '\n' >&2
    return 1
}

check_message() {
    local ret=0

    check_trailer "$1" "$2" "Signed-off-by" \
        "they have no meaning for NetworkManager" || ret=1
    check_trailer "$1" "$2" "Assisted-by" \
        "NetworkManager does not record tool assistance in commit messages" || ret=1
    return "$ret"
}

get_ci_base() {
    local base

    base="${CI_MERGE_REQUEST_DIFF_BASE_SHA:-}"
    if [ -n "$base" ]; then
        git cat-file -e "$base^{commit}" 2>/dev/null || die "\"$base\" is not a commit"
        printf '%s\n' "$base"
        return
    fi

    base="${CI_COMMIT_BEFORE_SHA:-}"
    if [ -n "$base" ] && git cat-file -e "$base^{commit}" 2>/dev/null; then
        printf '%s\n' "$base"
        return
    fi

    base="${CI_COMMIT_DEFAULT_BRANCH_BASE_SHA:-HEAD~1}"
    git cat-file -e "$base^{commit}" 2>/dev/null || die "\"$base\" is not a commit"
    printf '%s\n' "$base"
}

SUCCESS=0

check_range() {
    local range="$1"
    local refs
    local h

    refs="$(git log --reverse --format='%H' "$range")" || die "\"$range\" is not a valid range of commits"
    for h in $refs; do
        check_message "$(git log --format='%h (%s)' -1 "$h")" "$(git log --format='%B' -1 "$h")" || SUCCESS=1
    done
}

case "${1-}" in
    -h|--help)
        usage
        exit 0
        ;;
    --ci)
        test "$#" -eq 1 || die '"--ci" does not take arguments'
        check_range "$(get_ci_base)..HEAD"
        ;;
    --range)
        test "$#" -eq 2 || die "\"--range\" requires a git range"
        check_range "$2"
        ;;
    *)
        test "$#" -eq 1 || { usage >&2; exit 1; }
        test -f "$1" || die "\"$1\" is not a file"
        # Check the message as git will store it: git-stripspace drops the same
        # comment lines git does, honoring core.commentChar.
        check_message "$1" "$(git stripspace --strip-comments <"$1")" || SUCCESS=1
        ;;
esac

exit "$SUCCESS"
