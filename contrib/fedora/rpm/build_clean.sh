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
    echo "  -s|--snapshot TEXT: use TEXT as the snapshot version for the new package (overwrites \$NM_BUILD_SNAPSHOT environment)"
    echo "  -r|--release: built a release tarball (this option must be alone)"
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
SNAPSHOT="$NM_BUILD_SNAPSHOT"

ADD_WITH_TEST=1

NARGS=$#

while [[ $# -gt 0 ]]; do
    A="$1"
    shift
    case "$A" in
        -h|--help|-\?|help)
            usage
            exit 0
            ;;
        -f|--force)
            IGNORE_DIRTY=1
            ;;
        -r|--release)
            [[ $NARGS -eq 1 ]] || die "--release option must be alone"
            export NMTST_CHECK_GTK_DOC=1
            BUILDTYPE=SRPM
            ;;
        -c|--clean)
            GIT_CLEAN=1
            ;;
        -S|--srpm)
            BUILDTYPE=SRPM
            ;;
        -s|--snapshot)
            [[ $# -gt 0 ]] || die "Missing argument to $A"
            SNAPSHOT="$1"
            shift
            ;;
        -g|--git)
            NO_DIST=1
            IGNORE_DIRTY=1
            SOURCE_FROM_GIT=1
            ;;
        -Q|--quick)
            QUICK=1
            ;;
        -N|--no-dist)
            NO_DIST=1
            IGNORE_DIRTY=1
            SOURCE_FROM_GIT=0
            ;;
        -w|--with)
            [[ $# -gt 0 ]] || die "Missing argument to $A"
            WITH_LIST=("${WITH_LIST[@]}" "--with" "$1")
            if [[ "$1" == test ]]; then
                ADD_WITH_TEST=0
            fi
            shift
            ;;
        -W|--without)
            [[ $# -gt 0 ]] || die "Missing argument to $A"
            WITH_LIST=("${WITH_LIST[@]}" "--without" "$1")
            if [[ "$1" == test ]]; then
                ADD_WITH_TEST=0
            fi
            shift
            ;;
        *)
            usage
            die "Unexpected argument \"$A\""
            ;;
    esac
done

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
    ./autogen.sh \
        --program-prefix= \
        --prefix=/usr \
        --exec-prefix=/usr \
        --bindir=/usr/bin \
        --sbindir=/usr/sbin \
        --sysconfdir=/etc \
        --datadir=/usr/share \
        --includedir=/usr/include \
        --libdir=/usr/lib \
        --libexecdir=/usr/libexec \
        --localstatedir=/var \
        --sharedstatedir=/var/lib \
        --mandir=/usr/share/man \
        --infodir=/usr/share/info \
        \
        --disable-dependency-tracking \
        --enable-gtk-doc \
        --enable-introspection \
        --with-libnm-glib \
        --enable-ifcfg-rh \
        --enable-ifupdown \
        --enable-config-plugin-ibft \
        --with-config-logging-backend-default=syslog \
        --with-libaudit=yes-disabled-by-default \
        --enable-polkit=yes \
        --with-config-dhcp-default=internal \
        --with-config-dns-rc-manager-default=symlink \
        || die "Error autogen.sh"
    if [[ $QUICK == 1 ]]; then
        make dist -j 7 || die "Error make dist"
    else
        make distcheck -j 7 || die "Error make distcheck"
    fi
fi

if [[ "$ADD_WITH_TEST" == 1 ]]; then
    WITH_LIST=("${WITH_LIST[@]}" "--with" "test")
fi

export SOURCE_FROM_GIT
export BUILDTYPE
export NM_RPMBUILD_ARGS="${WITH_LIST[@]}"
export SNAPSHOT

"$SCRIPTDIR"/build.sh

