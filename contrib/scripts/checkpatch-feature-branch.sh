#!/bin/bash

die() {
    printf "%s\n" "$@"
    exit 1
}

HEAD="${1:-HEAD}"

BASE_DIR="$(dirname "$0")"

if printf '%s' "$HEAD" | grep -q '\.\.'; then
    # Check the explicitly specified range from the argument.
    REFS=( $(git log --reverse --format='%H' "$HEAD") ) || die "not a valid range (HEAD is $HEAD)"
else
    BASE_REF="refs/remotes/origin"
    NM_UPSTREAM_REMOTE=

    if [ "$NM_CHECKPATCH_FETCH_UPSTREAM" == 1 ]; then
        NM_UPSTREAM_REMOTE="nm-upstream-$(date '+%Y%m%d-%H%M%S')-$RANDOM"
        git remote add "$NM_UPSTREAM_REMOTE" https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git
        BASE_REF="refs/remotes/$NM_UPSTREAM_REMOTE"
        git fetch origin "$(git rev-parse "$HEAD")" --no-tags --unshallow
        git fetch "$NM_UPSTREAM_REMOTE" \
            --no-tags \
            "refs/heads/main:$BASE_REF/main" \
            "refs/heads/nm-*:$BASE_REF/nm-*" \
            || die "failure to fetch from https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git"
    else
        # A fork's main may contain unpublished commits, so prefer the
        # canonical repository when choosing which commits to exclude.
        while IFS= read -r REMOTE; do
            URL="$(git remote get-url "$REMOTE")" || continue
            URL="${URL%/}"
            case "${URL%.git}" in
                "https://gitlab.freedesktop.org/NetworkManager/NetworkManager"| \
                "git@gitlab.freedesktop.org:NetworkManager/NetworkManager"| \
                "git@ssh.gitlab.freedesktop.org:NetworkManager/NetworkManager"| \
                "ssh://git@gitlab.freedesktop.org/NetworkManager/NetworkManager"| \
                "ssh://git@ssh.gitlab.freedesktop.org/NetworkManager/NetworkManager")
                    BASE_REF="refs/remotes/$REMOTE"
                    break
                    ;;
            esac
        done < <(git remote)
    fi

    # the argument is only a single ref (or the default "HEAD").
    # Find all commits that branch off one of the stable branches or main
    # and lead to $HEAD. These are the commits of the feature branch.

    RANGES=()
    while read -r H REF; do
        REF="${REF#"$BASE_REF/"}"
        if [[ "$REF" == main || "$REF" =~ ^nm-1-[0-9]+$ ]]; then
            RANGES+=( "$H..$HEAD" )
        fi
    done < <(git for-each-ref --format='%(objectname) %(refname)' "$BASE_REF/")

    [ "${#RANGES[@]}" != 0 ] || die "cannot detect git-ranges (HEAD is $(git rev-parse "$HEAD"))"

    REFS=( $(git log --reverse --format='%H' "${RANGES[@]}") )

    if [ "${#REFS[@]}" == 0 ] ; then
        # no refs detected. This means, $HEAD is already on main (or one of the
        # stable nm-1-* branches. Just check the patch itself.
        REFS=( "$HEAD" )
    fi

    if [ -n "$NM_UPSTREAM_REMOTE" ]; then
        git remote remove "$NM_UPSTREAM_REMOTE"
    fi
fi

SUCCESS=0
for H in "${REFS[@]}"; do
    export NM_CHECKPATCH_HEADER=$'\n'">>> VALIDATE \"$(git log --oneline -n1 "$H")\""
    git format-patch -U65535 --stdout -1 "$H" | "$BASE_DIR/checkpatch.pl"
    if [ $? != 0 ]; then
        SUCCESS=1
    fi
done

exit $SUCCESS
