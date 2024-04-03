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
    echo "  $ $0 -r"
    echo
    echo "Options:"
    echo "  -f|--force: force build, even if working directory is not clean and has local modifications"
    echo "  -c|--clean: run \`git-clean -fdx :/\` before build"
    echo "  -S|--srpm: only build the SRPM"
    echo "  -g|--git: create tarball from current git HEAD (skips make dist)"
    echo "  -Q|--quick: only create the distribution tarball, without running checks"
    echo "  -N|--no-dist: skip creating the source tarball if you already did \`make dist\`"
    echo "  -m|--meson: (default) use meson to create the source tarball"
    echo "  -A|--autotools: use autotools to create the source tarball"
    echo "  -w|--with \$OPTION: pass --with \$OPTION to rpmbuild. For example --with debug"
    echo "  -W|--without \$OPTION: pass --without \$OPTION to rpmbuild. For example --without debug"
    echo "  -s|--snapshot TEXT: use TEXT as the snapshot version for the new package (overwrites \$NM_BUILD_SNAPSHOT environment)"
    echo "  -r|--release: built a release tarball (this option must be alone)"
    echo "  --default-for-debug \$OPTION: set the default for "debug" option in the generated spec file"
    echo "  --default-for-lto \$OPTION: set the default for "lto" option in the generated spec file"
    echo "  --default-for-test \$OPTION: set the default for "test" option in the generated spec file"
}

in_set() {
    local v="$1"
    shift
    for v2; do
        test "$v" = "$v2" && return 0
    done
    return 1
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
DO_RELEASE=0
unset BCOND_DEFAULT_DEBUG
unset BCOND_DEFAULT_LTO
unset BCOND_DEFAULT_TEST

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
            DO_RELEASE=1
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
        -m|--meson)
            [ "$USE_AUTOTOOLS" = 1 ] && die "conflicting argument: $A when building with autotools is requested";
            USE_MESON=1
            ;;
        -A|--autotools)
            [ "$USE_MESON" = 1 ] && die "conflicting argument: $A when building with meson is explicitly requested";
            USE_AUTOTOOLS=1
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
            case "$1" in
                debug)
                    [[ -z ${BCOND_DEFAULT_DEBUG+.} ]] && BCOND_DEFAULT_DEBUG=1
                    ;;
                lto)
                    [[ -z ${BCOND_DEFAULT_LTO+.} ]] && BCOND_DEFAULT_LTO=1
                    ;;
                test)
                    ADD_WITH_TEST=0
                    [[ -z ${BCOND_DEFAULT_TEST+.} ]] && BCOND_DEFAULT_TEST=1
                    ;;
            esac
            shift
            ;;
        -W|--without)
            [[ $# -gt 0 ]] || die "Missing argument to $A"
            WITH_LIST=("${WITH_LIST[@]}" "--without" "$1")
            case "$1" in
                debug)
                    [[ -z ${BCOND_DEFAULT_DEBUG+.} ]] && BCOND_DEFAULT_DEBUG=0
                    ;;
                lto)
                    [[ -z ${BCOND_DEFAULT_LTO+.} ]] && BCOND_DEFAULT_LTO=0
                    ;;
                test)
                    ADD_WITH_TEST=0
                    [[ -z ${BCOND_DEFAULT_TEST+.} ]] && BCOND_DEFAULT_TEST=0
                    ;;
            esac
            shift
            ;;
        --no-auto-with-test)
            # by default, the script adds "-w test" (unless the command line contains
            # "-w test" or "-W test"). This flags allows to suppress that automatism.
            # It's really only useful to test the spec file's internal default for the
            # "test" option. Otherwise, you can always just explicitly select "-w test"
            # or "-W test".
            ADD_WITH_TEST=0
            ;;
        --default-for-debug)
            [[ $# -gt 0 ]] || die "Missing argument to $A"
            in_set "$1" "" 0 1 || die "invalid argument $A \"$1\""
            BCOND_DEFAULT_DEBUG="$1"
            shift
            ;;
        --default-for-lto)
            [[ $# -gt 0 ]] || die "Missing argument to $A"
            in_set "$1" "" 0 1 || die "invalid argument $A \"$1\""
            BCOND_DEFAULT_LTO="$1"
            shift
            ;;
        --default-for-test)
            [[ $# -gt 0 ]] || die "Missing argument to $A"
            in_set "$1" "" 0 1 || die "invalid argument $A \"$1\""
            BCOND_DEFAULT_TEST="$1"
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

get_version_meson() {
    meson introspect "$GITDIR/build" --projectinfo | jq -r .version
}

if [[ $NO_DIST != 1 ]]; then
    if [[ $USE_AUTOTOOLS != 1 ]]; then
            meson setup "$GITDIR/build" \
                --prefix=/usr \
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
                -Ddocs=true \
                -Dintrospection=true \
                -Difcfg_rh=true \
                -Difupdown=true \
                -Dconfig_logging_backend_default=syslog \
                -Dconfig_wifi_backend_default=wpa_supplicant \
                -Dlibaudit=yes-disabled-by-default \
                -Dpolkit=true \
                -Dnm_cloud_setup=true \
                -Dconfig_dhcp_default=internal \
                -Dconfig_dns_rc_manager_default=auto \
                -Diptables=/usr/sbin/iptables \
                -Dnft=/usr/bin/nft \
                || die "Error meson setup"

            VERSION="${VERSION:-$(get_version_meson || die "Could not read $VERSION")}"
            if [[ $QUICK == 1 ]]; then
                meson dist --allow-dirty -C "$GITDIR/build/" --no-tests || die "Error meson dist"
            else
                meson dist --allow-dirty -C "$GITDIR/build/" || die "Error meson dist with tests"
            fi
            export SOURCE="$(ls -1 "$GITDIR/build/meson-dist/NetworkManager-${VERSION}.tar.xz" 2>/dev/null | head -n1)"
    else
        ./autogen.sh \
            --with-runstatedir=/run \
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
            --enable-ifcfg-rh \
            --enable-ifupdown \
            --with-config-logging-backend-default=syslog \
            --with-config-wifi-backend-default=wpa_supplicant \
            --with-libaudit=yes-disabled-by-default \
            --enable-polkit=yes \
            --with-nm-cloud-setup=yes \
            --with-config-dhcp-default=internal \
            --with-config-dns-rc-manager-default=auto \
            \
            --with-iptables=/usr/sbin/iptables \
            --with-nft=/usr/sbin/nft \
            \
            || die "Error autogen.sh"
        if [[ $QUICK == 1 ]]; then
            make dist -j 7 || die "Error make dist"
        else
            make distcheck -j 7 || die "Error make distcheck"
        fi
    fi
fi

if [[ "$ADD_WITH_TEST" == 1 ]]; then
    WITH_LIST=("${WITH_LIST[@]}" "--with" "test")
fi

if [[ "$USE_AUTOTOOLS" != 1 ]]; then
    WITH_LIST=("${WITH_LIST[@]}" "--with" "meson")
fi

export SOURCE_FROM_GIT
export BUILDTYPE
export NM_RPMBUILD_ARGS="${WITH_LIST[@]}"
export SNAPSHOT
export DO_RELEASE
export BCOND_DEFAULT_DEBUG="$BCOND_DEFAULT_DEBUG"
export BCOND_DEFAULT_LTO="$BCOND_DEFAULT_LTO"
export BCOND_DEFAULT_TEST="$BCOND_DEFAULT_TEST"

"$SCRIPTDIR"/build.sh

