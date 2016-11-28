#!/bin/bash


die() {
    echo "$*" >&2
    exit 1
}

usage() {
    echo "USAGE: $0 [-h|--help|-?|help] [-f|--force] [-c|--clean] [-S|--srpm] [-g|--git] [-Q|--quick] [-N|--no-dist] [[-w|--with OPTION] ...] [[-W|--without OPTION] ...]"
    echo
    echo "Does all the steps from a clean git working directory to an RPM of NetworkManager"
    echo
    echo "This is also the preferred way to create a distribution tarball for release:"
    echo "  $ $0 -c -S"
    echo
    echo "Options:"
    echo "  -f|--force: force build, even if working directory is not clean and has local modifications"
    echo "  -c|--clean: run \`git-clean -fdx :/\` before build"
    echo "  -S|--srpm: only build the SRPM"
    echo "  -g|--git: create tarball from current git HEAD (skips make dist)"
    echo "  -Q|--quick: only run \`make dist\` instead of \`make distcheck\`"
    echo "  -N|--no-dist: skip creating the source tarball if you already did \`make dist\`"
    echo "  -w|--with \$OPTION: pass --with \$OPTION to rpmbuild. For example --with debug"
    echo "  -W|--without \$OPTION: pass --without \$OPTION to rpmbuild. For example --without debug"
}


ORIGDIR="$(readlink -f "$PWD")"
SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
GITDIR="$(cd "$SCRIPTDIR" && git rev-parse --show-toplevel || die "Could not get GITDIR")"


[[ -x "$SCRIPTDIR"/build.sh ]] || die "could not find \"$SCRIPTDIR/build.sh\""

cd "$GITDIR" || die "could not change to $GITDIR"

IGNORE_DIRTY=0
GIT_CLEAN=0
QUICK=0
NO_DIST=0
WITH_LIST=()
SOURCE_FROM_GIT=0

_next_with=
for A; do
    if [ -n "$_next_with" ]; then
        WITH_LIST=("${WITH_LIST[@]}" "$_next_with" "$A")
        _next_with=
        continue
    fi
    case "$A" in
        -h|--help|-\?|help)
            usage
            exit 0
            ;;
        -f|--force)
            IGNORE_DIRTY=1
            ;;
        -c|--clean)
            GIT_CLEAN=1
            ;;
        -S|--srpm)
            BUILDTYPE=SRPM
            ;;
        -g|--git)
            NO_DIST=1
            IGNORE_DIRTY=1
            SOURCE_FROM_GIT=1
            ;;
        -Q|--quick)
            NO_DIST=0
            QUICK=1
            SOURCE_FROM_GIT=0
            ;;
        -N|--no-dist)
            NO_DIST=1
            IGNORE_DIRTY=1
            SOURCE_FROM_GIT=0
            ;;
        -w|--with)
            _next_with=--with
            ;;
        -W|--without)
            _next_with=--without
            ;;
        *)
            usage
            die "Unexpected argument \"$A\""
            ;;
    esac
done

test -n "$_next_with" && die "Missing argument to $_next_with"

if [[ $GIT_CLEAN == 1 ]]; then
    git clean -fdx :/
fi

if [[ $IGNORE_DIRTY != 1 ]]; then
    # check for a clean working directory.
    # We ignore the /contrib directory, because this is where the automation
    # scripts and the build results will be.
    if [[ "x$(LANG=C git clean -ndx | grep '^Would \(remove contrib/\|skip repository libgsystem/\).*$' -v)" != x ]]; then
        die "The working directory is not clean. Refuse to run. Try \`$0 --force\`, \`$0 --clean\`, or \`git clean -e :/contrib -dx -n\`"
    fi
    if [[ "x$(git status --porcelain)" != x ]]; then
        die "The working directory has local changes. Refuse to run. Try \`$0 --force\`"
    fi
fi

if [[ $NO_DIST != 1 ]]; then
    ./autogen.sh --enable-gtk-doc --enable-introspection --with-libnm-glib || die "Error autogen.sh"
    if [[ $QUICK == 1 ]]; then
        make dist -j 7 || die "Error make dist"
    else
        make distcheck -j 7 || die "Error make distcheck"
    fi
fi

export SOURCE_FROM_GIT
export BUILDTYPE
export NM_RPMBUILD_ARGS="${WITH_LIST[@]}"

"$SCRIPTDIR"/build.sh

