#!/bin/bash

set -e

while (( $# )); do
    case $1 in
        -i)
            FLAGS="-i"
            shift
            ;;
        -h)
            printf "Usage: %s [OPTION]... [FILE]...\n" $(basename $0)
            printf "Reformat source files using NetworkManager's code-style.\n\n"
            printf "If no file is given the script runs on the whole codebase.\n"
            printf "If no flag is given no file is touch but errors are reported.\n\n"
            printf "OPTIONS:\n"
            printf "    -i    Reformat files\n"
            printf "    -h    Print this help message\n"
            exit 0
            ;;
        *)
            FILES+=($1)
            shift
            ;;
    esac
done

NM_ROOT=$(git rev-parse --show-toplevel)
EXCLUDE=":(exclude)shared/systemd
         :(exclude)src/systemd
         :(exclude)shared/n-dhcp4
         :(exclude)shared/c-list
         :(exclude)shared/c-list
         :(exclude)shared/c-list
         :(exclude)shared/c-rbtree
         :(exclude)shared/c-siphash
         :(exclude)shared/c-stdaux
         :(exclude)shared/n-acd"

if ! which clang-format &> /dev/null; then
    echo -n "Error: clang-format is not installed, "
    echo "on RHEL/Fedora/CentOS run 'dnf install clang-tools-extra'"
    exit 1
fi

if [ ! -f ${NM_ROOT}/.clang-format ]; then
    echo "Error: the clang-format file does not exist"
    exit 1
fi


FLAGS=${FLAGS:-"--Werror -n --ferror-limit=1"}

if [ -z "${FILES[@]}" ]; then
    cd $NM_ROOT
    FILES=($(git ls-files --full-name -- '*.[ch]' ${EXCLUDE}))
fi

for f in "${FILES[@]}"; do
    if [ -f $f ]; then
        if ! clang-format $FLAGS $f &> /dev/null; then
            TMP_FILE=$(mktemp)
            clang-format $f > $TMP_FILE
            git --no-pager diff $f $TMP_FILE || true
            rm $TMP_FILE
            echo "Error: $(basename $f) code-style is wrong, fix it by running '$0 -i $f)"
            exit 1
        fi
   else
        echo "Error: $f No such file"
   fi
done
