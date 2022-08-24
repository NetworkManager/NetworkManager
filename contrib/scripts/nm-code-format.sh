#!/bin/bash

set -e

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

EXCLUDE_PATHS_TOPLEVEL=(
    "src/c-list"
    "src/c-rbtree"
    "src/c-siphash"
    "src/c-stdaux"
    "src/libnm-std-aux/unaligned.h"
    "src/libnm-systemd-core/src"
    "src/libnm-systemd-shared/src"
    "src/linux-headers"
    "src/n-acd"
    "src/n-dhcp4"
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
    EXCLUDE_PATHS=()
    for e in "${EXCLUDE_PATHS_TOPLEVEL[@]}"; do
        REGEX="^$NM_PREFIX([^/].*)$"
        if [[ "$e" =~ $REGEX ]]; then
            EXCLUDE_PATHS+=("${BASH_REMATCH[1]}")
        fi
    done
else
    EXCLUDE_PATHS=("${EXCLUDE_PATHS_TOPLEVEL[@]}")
fi

FILES=()
HAS_EXPLICIT_FILES=0
SHOW_FILENAMES=0
TEST_ONLY=0
CHECK_ALL=1

usage() {
    printf "Usage: %s [OPTION]... [FILE]...\n" "$(basename "$0")"
    printf "Reformat source files using NetworkManager's code-style.\n\n"
    printf "If no file is given the script runs on the whole codebase.\n"
    printf "OPTIONS:\n"
    printf "    -h                 Print this help message.\n"
    printf "    -i                 Reformat files (the default).\n"
    printf "    -n|--dry-run       Only check the files (contrary to \"-i\").\n"
    printf "    -a|--all           Check all files (the default).\n"
    printf "    -F|--fast          Check only files from \`git diff --name-only HEAD^\` (contrary to \"-a\").\n"
    printf "                       This also affects directories given in the [FILE] list, but not files.\n"
    printf "    --show-filenames   Only print the filenames that would be checked/formatted\n"
    printf "    --                 Separate options from filenames/directories\n"
}

ls_files_filter() {
    local OLD_IFS="$IFS"

    IFS=$'\n'
    for f in $(cat) ; do
        local found=1
        local p
        for p; do
            [[ "$f" = "$p/"* ]] && found=
            [[ "$f" = "$p" ]] && found=
        done
        test -n "$found" && printf '%s\n' "$f"
    done
    IFS="$OLD_IFS"
}

g_ls_files() {
    local pattern="$1"
    shift

    if [ $CHECK_ALL = 1 ]; then
        git ls-files -- "$pattern"
    else
        git diff --name-only HEAD^ -- "$pattern"
    fi | ls_files_filter "$@"
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
            -a|--all)
                CHECK_ALL=1
                shift
                continue
                ;;
            -F|--fast)
                CHECK_ALL=0
                shift
                continue
                ;;
            -n|--dry-run)
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
        while IFS='' read -r line;
            do FILES+=("$line")
        done < <(CHECK_ALL=$CHECK_ALL g_ls_files "${1}/*.[hc]" "${EXCLUDE_PATHS[@]}")
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
    while IFS='' read -r line; do
        FILES+=("$line")
    done < <(CHECK_ALL=$CHECK_ALL g_ls_files '*.[ch]' "${EXCLUDE_PATHS[@]}")
fi

if [ $SHOW_FILENAMES = 1 ]; then
    for f in "${FILES[@]}" ; do
        printf '%s\n' "$f"
    done
    exit 0
fi

if [ "${#FILES[@]}" = 0 ]; then
    if [ $CHECK_ALL = 1 ]; then
        die "Error: no files to check"
    fi
    exit 0
fi

FLAGS_TEST=( --Werror -n --ferror-limit=1 )

if [ $TEST_ONLY = 1 ]; then
    # We assume that all formatting is correct. In that mode, passing
    # all filenames to clang-format is significantly faster.
    #
    # Only in case of an error, we iterate over the files one by one
    # until we find the first invalid file.
    for f in "${FILES[@]}"; do
        [ -f "$f" ] || die "Error: file \"$f\" does not exist (or is not a regular file)"
    done
    clang-format "${FLAGS_TEST[@]}" "${FILES[@]}" &>/dev/null && exit 0
    for f in "${FILES[@]}"; do
        [ -f "$f" ] || die "Error: file \"$f\" does not exist (or is not a regular file)"
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
