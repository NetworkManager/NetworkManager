#!/bin/bash

# Arguments via environment variables:
#  - CI
#  - CC
#  - CFLAGS
#  - WITH_DOCS

set -ex

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
if command -v ccache &>/dev/null; then
    USE_CCACHE=1
    export PATH="/usr/lib64/ccache:/usr/lib/ccache${PATH:+:${PATH}}"
fi

IS_FEDORA=0
IS_CENTOS=0
IS_ALPINE=0
grep -q '^NAME=.*\(CentOS\)' /etc/os-release && IS_CENTOS=1
grep -q '^NAME=.*\(Fedora\)' /etc/os-release && IS_FEDORA=1
grep -q '^NAME=.*\(Alpine\)' /etc/os-release && IS_ALPINE=1

###############################################################################

_WITH_CRYPTO="gnutls"
_WITH_WERROR=1
_WITH_LIBTEAM="true"
_WITH_DOCS="true"
_WITH_SYSTEMD_LOGIND="true"
_WITH_NBFT="true"
if [ $IS_ALPINE = 1 ]; then
    _WITH_SYSTEMD_LOGIND="false"
fi

if ! pkgconf 'libnvme >= 1.5'; then
    _WITH_NBFT="false"
fi

if [ -z "${NMTST_SEED_RAND+x}" ]; then
    NMTST_SEED_RAND="$SRANDOM"
    if [ -z "$NMTST_SEED_RAND" ]; then
        NMTST_SEED_RAND="$(( ( (RANDOM<<15|RANDOM)<<15|RANDOM ) % 0xfffffffe ))"
    fi
fi
export NMTST_SEED_RAND

case "$CI" in
    ""|"true"|"default"|"gitlab")
        CI=default
        ;;
    *)
        die "invalid \$CI \"$CI\""
        ;;
esac

if [ "$CC" != gcc ]; then
    _WITH_CRYPTO=nss
fi

if [ "$WITH_LIBTEAM" != "" ]; then
    if _is_true "$WITH_LIBTEAM"; then
        _WITH_LIBTEAM="true"
    else
        _WITH_LIBTEAM="false"
    fi
fi

if [ "$WITH_DOCS" != "" ]; then
    if _is_true "$WITH_DOCS"; then
        _WITH_DOCS="true"
    else
        _WITH_DOCS="false"
    fi
fi

unset _WITH_VALGRIND_CHECKED
_with_valgrind() {
    _is_true "$WITH_VALGRIND" 0 || return 1

    test "$_WITH_VALGRIND_CHECKED" = "1" && return 0
    _WITH_VALGRIND_CHECKED=1

    if [ "$IS_ALPINE" = 1 ]; then
        # on Alpine we have no debug symbols and the suppressions
        # don't work. Skip valgrind tests.
        WITH_VALGRIND=0
    fi

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
    elif grep -q '^PRETTY_NAME="Debian.*sid"$' /etc/os-release; then
        if dpkg -s libglib2.0-bin | grep -q '^Version: 2.66.4-2$' ; then
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

###############################################################################

if [ "$_WITH_WERROR" == 1 ]; then
    _WITH_WERROR_VAL="--werror"
else
    _WITH_WERROR_VAL=""
fi

meson setup build \
    \
    -Dprefix="$PWD/INST" \
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
    -D dhcpcd=/bin/nowhere/dhcpd \
    \
    -D netconfig=/bin/nowhere/netconfig \
    -D resolvconf=/bin/nowhere/resolvconf \
    \
    -D ifcfg_rh=false \
    -D ifupdown=true \
    \
    -D nbft=$_WITH_NBFT \
    \
    #end

export NM_TEST_CLIENT_CHECK_L10N=1

if [ "$CONFIGURE_ONLY" != 1 ]; then
    ninja -C build -v
    ninja -C build install

    if ! meson test -C build -v --print-errorlogs ; then
        echo ">>>> RUN SECOND TEST (start)"
        NMTST_DEBUG="debug,TRACE,no-expect-message" \
        meson test -C build -v --print-errorlogs || :
        echo ">>>> RUN SECOND TEST (done)"
        die "meson test failed"
    fi

    if _with_valgrind; then
        if ! NMTST_USE_VALGRIND=1 meson test -C build -v --print-errorlogs ; then
            _print_test_logs "(valgrind test)"
            die "meson+valgrind test failed"
        fi
    fi
fi

if [ "$USE_CCACHE" = 1 ]; then
    echo "ccache statistics:"
    ccache -s
fi
