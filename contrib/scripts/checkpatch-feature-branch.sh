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
    BASE_REF="refs/remotes/origin/"

    # the argument is only a single ref (or the default "HEAD").
    # Find all commits that branch off one of the stable branches or master
    # and lead to $HEAD. These are the commits of the feature branch.

    RANGES=( $(git show-ref | sed 's#^\(.*\) '"$BASE_REF"'\(master\|nm-1-[0-9]\+\)$#\1..'"$HEAD"'#p' -n) )

    [ "${#RANGES[@]}" != 0 ] || die "cannot detect git-ranges (HEAD is $(git rev-parse "$HEAD"))"

    REFS=( $(git log --reverse --format='%H' "${RANGES[@]}") )

    if [ "${#REFS[@]}" == 0 ] ; then
        # no refs detected. This means, $HEAD is already on master (or one of the
        # stable nm-1-* branches. Just check the patch itself.
        REFS=( "$HEAD" )
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
