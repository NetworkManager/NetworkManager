#!/bin/bash

# Arguments via environment variables:
#  - CI
#  - CC
#  - BUILD_TYPE
#  - CFLAGS
#  - WITH_DOCS

set -exv

die() {
    printf "%s\n" "$@"
    exit 1
}

_is_true() {
    case "$1" in
        1|y|yes|YES|Yes|on)
            return 0
            ;;
        0|n|no|NO|No|off)
            return 1
            ;;
        *)
            die "not a boolean argument \"$1\""
            ;;
    esac
}

if which ccache &>/dev/null; then
    export PATH="/usr/lib64/ccache:/usr/lib/ccache${PATH:+:${PATH}}"
fi

###############################################################################

if [ "$BUILD_TYPE" == meson ]; then
    _TRUE=true
    _FALSE=false
elif [ "$BUILD_TYPE" == autotools ]; then
    _TRUE=yes
    _FALSE=no
else
    die "invalid \$BUILD_TYPE \"$BUILD_TYPE\""
fi

_WITH_CRYPTO="gnutls"
_WITH_WERROR=1
_WITH_LIBTEAM="$_TRUE"
_WITH_DOCS="$_TRUE"
_WITH_SYSTEMD_LOGIND="$_TRUE"

if [ "$CI" == travis ]; then
    _WITH_WERROR=0
    _WITH_LIBTEAM="$_FALSE"
    _WITH_DOCS="$_FALSE"
    _WITH_SYSTEMD_LOGIND="$_FALSE"
elif [ "$CI" == gitlab ]; then
    :
else
   die "invalid \$CI \"$CI\""
fi
if [ "$CC" != gcc ]; then
    _WITH_CRYPTO=nss
fi

if [ "$WITH_DOCS" != "" ]; then
    if _is_true "$WITH_DOCS"; then
        _WITH_DOCS="$_TRUE"
    else
        _WITH_DOCS="$_FALSE"
    fi
fi

###############################################################################

_autotools_test_print_logs() {
    echo ">>>> PRINT TEST LOGS $1 (start)"
    cat test-suite.log
    echo ">>>> PRINT TEST LOGS $1 (done)"
}

run_autotools() {
    NOCONFIGURE=1 ./autogen.sh
    mkdir ./build
    if [ "$_WITH_WERROR" == 1 ]; then
        _WITH_WERROR_VAL="error"
    else
        _WITH_WERROR_VAL="yes"
    fi
    pushd ./build
        ../configure \
            --prefix="$PWD/INST" \
            --enable-introspection=$_WITH_DOCS \
            --enable-gtk-doc=$_WITH_DOCS \
            --with-systemd-logind=$_WITH_SYSTEMD_LOGIND \
            --enable-more-warnings="$_WITH_WERROR_VAL" \
            --enable-tests=yes \
            --with-crypto=$_WITH_CRYPTO \
            \
            --with-libnm-glib=yes \
            --with-iwd=yes \
            --with-ofono=yes \
            --enable-teamdctl=$_WITH_LIBTEAM \
            \
            --with-dhcpcanon=yes \
            --with-dhcpcd=yes \
            --with-dhclient=yes \
            \
            --with-netconfig=/bin/nowhere/netconfig \
            --with-resolvconf=/bin/nowhere/resolvconf \
            \
            --enable-ifcfg-rh=yes \
            --enable-config-plugin-ibft=yes \
            --enable-ifupdown=yes \
            \
            #end

        make -j 6
        make install

        export NM_TEST_CLIENT_CHECK_L10N=1

        if [ "$CI" == travis ]; then
            # travis is known to generate the settings doc differently.
            # Don't compare.
            export NMTST_NO_CHECK_SETTINGS_DOCS=yes
        fi

        if ! make check -j 6 -k ; then

            _autotools_test_print_logs "first-test"

            echo ">>>> RUN SECOND TEST (start)"
            NMTST_DEBUG=TRACE,no-expect-message make check -k || :
            echo ">>>> RUN SECOND TEST (done)"

            _autotools_test_print_logs "second-test"
            die "test failed"
        fi
    popd
}

###############################################################################

run_meson() {
    if [ "$_WITH_WERROR" == 1 ]; then
        _WITH_WERROR_VAL="--werror"
    else
        _WITH_WERROR_VAL=""
    fi
    meson build \
        \
        --warnlevel 2 \
        $_WITH_WERROR_VAL \
        \
        -D ld_gc=false \
        -D session_tracking=no \
        -D systemdsystemunitdir=no \
        -D systemd_journal=false \
        -D selinux=false \
        -D libaudit=no \
        -D libpsl=false \
        -D vapi=false \
        -D introspection=$_WITH_DOCS \
        -D qt=false \
        -D crypto=$_WITH_CRYPTO \
        -D docs=$_WITH_DOCS \
        \
        -D libnm_glib=true \
        -D iwd=true \
        -D ofono=true \
        -D teamdctl=$_WITH_LIBTEAM \
        \
        -D dhclient=/bin/nowhere/dhclient \
        -D dhcpcanon=/bin/nowhere/dhcpcanon \
        -D dhcpcd=/bin/nowhere/dhcpd \
        \
        -D netconfig=/bin/nowhere/netconfig \
        -D resolvconf=/bin/nowhere/resolvconf \
        \
        -D ifcfg_rh=false \
        -D ibft=true \
        -D ifupdown=true \
        \
        #end

    ninja -C build
    ninja -C build test
}

###############################################################################

if [ "$BUILD_TYPE" == autotools ]; then
    run_autotools
elif [ "$BUILD_TYPE" == meson ]; then
    run_meson
fi
