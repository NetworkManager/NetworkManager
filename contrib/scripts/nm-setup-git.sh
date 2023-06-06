#!/bin/bash

set -e

usage() {
    printf "%s [--no-test]\n" "$CMD_NAME"
    printf "\n"
    printf "This script configures (or shows configuration) to the local git, with\n"
    printf "settings that might be useful when working on NetworkManager.\n"
    printf "\n"
    printf "RUn it without arguments, it only prints and shows what it would do.\n"
    printf "\n"
    printf "  --no-test: by default, the script only prints what it\n"
    printf "    would do. You can also set NO_TEST=1 environment variable.\n"
    printf "\n"
}

get_bool() {
    local name="$1"
    local val="${!name}"

    case "$val" in
        1|y|yes|Yes|YES|true|True|TRUE|on|On|ON)
            echo -n 1
            return 0
            ;;
        0|n|no|No|NO|false|False|FALSE|off|Off|OFF)
            echo -n 0
            return 0
            ;;
        *)
            printf "%s" "$2"
            ;;
    esac
}

die() {
    echo "ERROR: $*"
    exit 1
}

_pprint() {
    local a
    local sp=''

    for a; do
        printf "$sp%q" "$a"
        sp=' '
    done
}

call() {
    local m=""

    [ "$SKIP" = 1 ] && m="SKIP: "

    if [ "$NO_TEST" != 1 ]; then
        printf "WOULD: %s%s\n" "$m" "$(_pprint "$@")"
        return 0
    fi
    printf "CALL: %s%s\n" "$m" "$(_pprint "$@")"
    [ "$SKIP" = 1 ] || "$@"
}

git_config_reset() {
    local key="$1"
    local val="$2"
    local c=(git config --replace-all "$key" "$val")

    test "$#" -eq 2 || die "invalid arguments to git_config_add(): $@"

    if [ "$(git config --get-all "$key")" = "$val" ]; then
        SKIP=1 call "${c[@]}"
        return 0
    fi
    call "${c[@]}"
}

git_config_add() {
    local key="$1"
    local val="$2"
    local c=(git config --add "$key" "$val")

    test "$#" -eq 2 || die "invalid arguments to git_config_add(): $@"

    if git config --get-all "$key" | grep -qFx "$val"; then
        SKIP=1 call "${c[@]}"
        return 0
    fi
    call "${c[@]}"
}

CMD_NAME="$0"
NO_TEST="$(get_bool NO_TEST 0)"

for a; do
    case "$a" in
        --no-test)
            NO_TEST=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            die "Invalid argument \"$a\""
            ;;
    esac
done

case "$(git config --get-all remote.origin.url)" in
    "https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git"| \
    "git@gitlab.freedesktop.org:NetworkManager/NetworkManager.git"| \
    "ssh://git@gitlab.freedesktop.org/NetworkManager/NetworkManager")
        ;;
    *)
        die "unexpected git repository. Expected that remote.origin.url is set to \"https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git\""
        ;;
esac

git_config_add blame.ignoreRevsFile '.git-blame-ignore-revs'
git_config_reset blame.markIgnoredLines true
git_config_reset blame.markUnblamableLines true
git_config_add notes.displayref 'refs/notes/bugs'
git_config_add remote.origin.fetch 'refs/notes/bugs:refs/notes/bugs'
git_config_reset remote.origin.pushurl 'git@gitlab.freedesktop.org:NetworkManager/NetworkManager.git'
git_config_add 'alias.backport-merge' '! (git show main:contrib/scripts/git-backport-merge || git show origin/main:contrib/scripts/git-backport-merge) | bash -s -'

if [ "$NO_TEST" != 1 ]; then
    printf "Run with \"--no-test\" or see \"-h\"\n" >&2
    printf "\n" >&2
    printf "    \"%s\" --no-test\n" "$CMD_NAME" >&2
fi
