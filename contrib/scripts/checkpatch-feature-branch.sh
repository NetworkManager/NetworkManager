#!/bin/bash

die() {
	printf "%s\n" "$@"
	exit 1
}

HEAD="${1:-HEAD}"

BASE_DIR="$(dirname "$0")"

BASE_REF="refs/remotes/origin/"

RANGES=( $(git show-ref | sed 's#^\(.*\) '"$BASE_REF"'\(master\|nm-1-[0-9]\+\)$#\1..'"$HEAD"'#p' -n) )

[ "${#RANGES[@]}" != 0 ] || die "cannot detect git-ranges (HEAD is $(git rev-parse HEAD))"

REFS=( $(git log --reverse --format='%H' "${RANGES[@]}") )

[ "${#REFS[@]}" != 0 ] || die "no refs detected (HEAD is $(git rev-parse HEAD))"

SUCCESS=0
for H in ${REFS[@]}; do
    export NM_CHECKPATCH_HEADER=$'\n'">>> VALIDATE \"$(git log --oneline -n1 "$H")\""
    git format-patch -U65535 --stdout -1 "$H" | "$BASE_DIR/checkpatch.pl"
    if [ $? != 0 ]; then
        SUCCESS=1
    fi
done

exit $SUCCESS
