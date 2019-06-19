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
        "")
            if [ "$2" == "" ]; then
                die "not a boolean argument \"$1\""
            fi
            _is_true "$2"
            return $?
            ;;
        *)
            die "not a boolean argument \"$1\""
            ;;
    esac
}

USE_CCACHE=0
if which ccache &>/dev/null; then
    USE_CCACHE=1
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

if [ "$NMTST_SEED_RAND" != "" ]; then
    export NMTST_SEED_RAND=
fi

case "$CI" in
    ""|"true"|"default"|"gitlab")
        CI=default
        ;;
    "travis")
        _WITH_WERROR=0
        _WITH_LIBTEAM="$_FALSE"
        _WITH_DOCS="$_FALSE"
        _WITH_SYSTEMD_LOGIND="$_FALSE"
        ;;
    *)
        die "invalid \$CI \"$CI\""
        ;;
esac

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

unset _WITH_VALGRIND_CHECKED
_with_valgrind() {
    _is_true "$WITH_VALGRIND" 0 || return 1

    test "$_WITH_VALGRIND_CHECKED" == "1" && return 0
    _WITH_VALGRIND_CHECKED=1

    # Certain glib2 versions are known to report *lots* of leaks. Disable
    # valgrind tests in this case.
    # https://bugzilla.redhat.com/show_bug.cgi?id=1710417
    if grep -q '^PRETTY_NAME="Fedora 30 (.*)"$' /etc/os-release ; then
        if rpm -q glib2 | grep -q glib2-2.60.2-1.fc30 ; then
            WITH_VALGRIND=0
        fi
    elif grep -q '^PRETTY_NAME="Fedora 31 (.*)"$' /etc/os-release; then
        if rpm -q glib2 | grep -q glib2-2.61.0-2.fc31 ; then
            WITH_VALGRIND=0
        fi
    fi
    if [ "$WITH_VALGRIND" == 0 ]; then
        echo "Don't use valgrind due to known issues in other packages."
        return 1
    fi
    return 0
}

###############################################################################

_print_test_logs() {
    echo ">>>> PRINT TEST LOGS $1 (start)"
    if test -f test-suite.log; then
        cat test-suite.log
    fi
    echo ">>>> PRINT TEST LOGS $1 (done)"
    if _with_valgrind; then
        echo ">>>> PRINT VALGRIND LOGS $1 (start)"
        find -name '*.valgrind-log' -print0 | xargs -0 grep -H ^ || true
        echo ">>>> PRINT VALGRIND LOGS $1 (done)"
    fi
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
            --with-ebpf=no \
            \
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

            _print_test_logs "first-test"

            echo ">>>> RUN SECOND TEST (start)"
            NMTST_DEBUG=TRACE,no-expect-message make check -k || :
            echo ">>>> RUN SECOND TEST (done)"

            _print_test_logs "second-test"
            die "test failed"
        fi

        if _with_valgrind; then
            if ! NMTST_USE_VALGRIND=1 make check -j 3 -k ; then
                _print_test_logs "(valgrind test)"
                die "valgrind test failed"
            fi
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
        -D ebpf=false \
        \
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
        -D ifupdown=true \
        \
        #end

    ninja -C build
    ninja -C build test

    if _with_valgrind; then
        if ! NMTST_USE_VALGRIND=1 ninja -C build test; then
            _print_test_logs "(valgrind test)"
            die "valgrind test failed"
        fi
    fi
}

###############################################################################

if [ "$BUILD_TYPE" == autotools ]; then
    run_autotools
elif [ "$BUILD_TYPE" == meson ]; then
    run_meson
fi

if [ "$USE_CCACHE" = 1 ]; then
    echo "ccache statistics:"
    ccache -s
fi
