#!/bin/bash

set -e

_print() {
    printf '%s\n' "$*" >&2
}

die() {
    _print "$*"
    exit 1
}

NM_ROOT="$(git rev-parse --show-toplevel)" || die "not inside a git repository"
NM_PREFIX="$(git rev-parse --show-prefix)" || die "not inside a git repository"

cd "$NM_ROOT" || die "failed to cd into \$NM_ROOT\""

if [ ! -f "./src/core/main.c" ]; then
    die "Error: \"$NM_ROOT\" does not look like NetworkManager source tree"
fi

BLACK="${BLACK:-black}"

if ! command -v "$BLACK" &> /dev/null; then
    _print "Error: black is not installed. On RHEL/Fedora/CentOS run 'dnf install black'"
    exit 77
fi

OLD_IFS="$IFS"

usage() {
    printf "Usage: %s [OPTION]... [FILE]...\n" "$(basename "$0")"
    printf "Reformat python source files using python black.\n"
    printf "Without FILE arguments, all python files of the source tree are used.\n\n"
    printf "OPTIONS:\n"
    printf "    -i                   Reformat files (this is the default)\n"
    printf "    -n|--dry-run|--check Only check the files (contrary to \"-i\")\n"
    printf "    --show-filenames     Only print the filenames that would be checked/formatted\n"
    printf "    -h                   Print this help message\n"
}

TEST_ONLY=0
SHOW_FILENAMES=0
FILES_ARG=()

while (( $# )); do
    case "$1" in
        -h)
            usage
            exit 0
            ;;
        -n|--dry-run|--check)
            TEST_ONLY=1
            shift
            continue
            ;;
        -i)
            TEST_ONLY=0
            shift
            continue
            ;;
        --show-filenames)
            SHOW_FILENAMES=1
            shift
            continue
            ;;
        -*)
            usage
            exit 1
            ;;
        *)
            FILES_ARG+=( "$1" )
            shift
            continue
            ;;
    esac
done

IFS=$'\n'
FILES=()
if [ "${#FILES_ARG[@]}" -gt 0 ]; then
    FILES=( "${FILES_ARG[@]}" )
else
    FILES+=( $(git ls-tree --name-only -r HEAD | grep '\.py$') )
    FILES+=( $(git grep -l '#!.*\<p[y]thon3\?\>') )
fi
FILES=( $(printf "%s\n" "${FILES[@]}" | sort -u) )

# Filter out paths that are forked from upstream projects and not
# ours to reformat.
FILES=( $(
    printf "%s\n" "${FILES[@]}" |
    sed \
        -e '/^src\/[cn]-[^/]\+\//d' \
        -e '/^src\/libnm-systemd-[^/]\+\/src\//d'
) )

IFS="$OLD_IFS"

if [ $SHOW_FILENAMES = 1 ]; then
    printf '%s\n' "${FILES[@]}"
    exit 0
fi

if [ "${#FILES[@]}" -eq 0 ]; then
    exit 0
fi

EXTRA_ARGS=()
if [ $TEST_ONLY = 1 ]; then
    EXTRA_ARGS+=('--check')
fi

"$BLACK" "${EXTRA_ARGS[@]}" "${FILES[@]}"
