#!/bin/bash

set -e

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

EXCLUDE=(
    ":(exclude)shared/c-list"
    ":(exclude)shared/c-list"
    ":(exclude)shared/c-list"
    ":(exclude)shared/c-rbtree"
    ":(exclude)shared/c-siphash"
    ":(exclude)shared/c-stdaux"
    ":(exclude)shared/n-acd"
    ":(exclude)shared/n-dhcp4"
    ":(exclude)shared/nm-std-aux/unaligned.h"
    ":(exclude)shared/systemd/src"
    ":(exclude)src/systemd/src"
)

NM_ROOT="$(git rev-parse --show-toplevel)" || die "not inside a git repository"
NM_PREFIX="$(git rev-parse --show-prefix)" || die "not inside a git repository"

if [ ! -f "$NM_ROOT/.clang-format" ]; then
    die "Error: the clang-format file in \"$NM_ROOT\" does not exist"
fi

if ! command -v clang-format &> /dev/null; then
    die "Error: clang-format is not installed. On RHEL/Fedora/CentOS run 'dnf install clang-tools-extra'"
fi

if test -n "$NM_PREFIX"; then
    _EXCLUDE=()
    for e in "${EXCLUDE[@]}"; do
        REGEX='^:\(exclude\)'"$NM_PREFIX"'([^/].*)$'
        if [[ "$e" =~ $REGEX ]]; then
            _EXCLUDE+=(":(exclude)${BASH_REMATCH[1]}")
        fi
    done
    EXCLUDE=("${_EXCLUDE[@]}")
fi

FILES=()
HAS_EXPLICIT_FILES=0
SHOW_FILENAMES=0
TEST_ONLY=1

usage() {
    printf "Usage: %s [OPTION]... [FILE]...\n" $(basename $0)
    printf "Reformat source files using NetworkManager's code-style.\n\n"
    printf "If no file is given the script runs on the whole codebase.\n"
    printf "If no flag is given no file is touch but errors are reported.\n\n"
    printf "OPTIONS:\n"
    printf "    -i                 Reformat files\n"
    printf "    -n                 Only check the files (this is the default)\n"
    printf "    -h                 Print this help message\n"
    printf "    --show-filenames   Only print the filenames that would be checked\n"
    printf "    --                 Separate options from filenames/directories\n"
}

HAD_DASHDASH=0
while (( $# )); do
    if [ "$HAD_DASHDASH" = 0 ]; then
        case "$1" in
            -h)
                usage
                exit 0
                ;;
            --show-filenames)
                SHOW_FILENAMES=1
                shift
                continue
                ;;
            -n)
                TEST_ONLY=1
                shift
                continue
                ;;
            -i)
                TEST_ONLY=0
                shift
                continue
                ;;
            --)
                HAD_DASHDASH=1
                shift
                continue
                ;;
        esac
    fi
    if [ -d "$1" ]; then
        FILES+=( $(git ls-files -- "${1}/*.[hc]" "${EXCLUDE[@]}" ) )
    elif [ -f "$1" ]; then
        FILES+=("$1")
    else
        usage >&2
        echo >&2
        die "Unknown argument \"$1\" which also is neither a file nor a directory."
    fi
    shift
    HAS_EXPLICIT_FILES=1
done

if [ $HAS_EXPLICIT_FILES = 0 ]; then
    FILES=( $(git ls-files -- '*.[ch]' "${EXCLUDE[@]}")  )
fi

if [ $SHOW_FILENAMES = 1 ]; then
    printf '%s\n' "${FILES[@]}"
    exit 0
fi

if [ "${#FILES[@]}" = 0 ]; then
    die "Error: no files to check"
fi

FLAGS_TEST=( --Werror -n --ferror-limit=1 )

if [ $TEST_ONLY = 1 ]; then
    # We assume that all formatting is correct. In that mode, passing
    # all filenames to clang-format is significantly faster.
    #
    # Only in case of an error, we iterate over the files one by one
    # until we find the first invalid file.
    for f in "${FILES[@]}"; do
        [ -f $f ] || die "Error: file \"$f\" does not exist (or is not a regular file)"
    done
    clang-format "${FLAGS_TEST[@]}" "${FILES[@]}" &>/dev/null && exit 0
    for f in "${FILES[@]}"; do
        [ -f $f ] || die "Error: file \"$f\" does not exist (or is not a regular file)"
        if ! clang-format "${FLAGS_TEST[@]}" "$f" &>/dev/null; then
            FF="$(mktemp)"
            trap 'rm -f "$FF"' EXIT
            clang-format "$f" 2>/dev/null > "$FF"
            git --no-pager diff "$f" "$FF" || :
            die "Error: file \"$f\" has code-style is wrong. Fix it by running "'`'"\"$0\" -i \"$f\""'`'
        fi
    done
    die "an unknown error happened."
fi

clang-format -i "${FILES[@]}"
