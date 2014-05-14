#!/bin/bash


die() {
    echo "$*" >&2
    exit 1
}

# copy output also to logfile
LOG() {
    echo "$*"
}


ORIGDIR="$(readlink -f "$PWD")"
SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
GITDIR="$(cd "$SCRIPTDIR" && git rev-parse --show-toplevel || die "Could not get GITDIR")"


[[ -x "$SCRIPTDIR"/build.sh ]] || die "could not find \"$SCRIPTDIR/build.sh\""

cd "$GITDIR" || die "could not change to $GITDIR"

# check for a clean working directory.
# We ignore the /contrib directory, because this is where the automation
# scripts and the build results will be.
if [[ "x$(git clean -ndx | grep '^Would remove contrib/.*$' -v)" != x ]]; then
    die "The working copy is not clean. Refuse to run. Try    git clean -e /contrib -dx -n"
fi

./autogen.sh --enable-gtk-doc || die "Error autogen.sh"
make -j 10 || die "Error make"

make distcheck || die "Error make distcheck"

"$SCRIPTDIR"/build.sh
