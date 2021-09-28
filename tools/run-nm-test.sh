#!/bin/bash

die() {
    echo "$@"
    exit 5
}

_is_true() {
    case "$1" in
        y|Y|yes|YES|1|true|TRUE)
            return 0
            ;;
        n|N|no|NO|0|false|FALSE)
            return 1
            ;;
        *)
            if test -n "$2"; then
                _is_true "$2"
                return $?
            fi
            return 2
            ;;
    esac
}

usage() {
    echo "$0 [\$OPTIONS] [--] \$TEST [\$TEST_OPTIONS]"
    echo ""
    echo "  Runs the unit test with setting up dbus-session (as necessary),"
    echo "  optionally build the test first, and run valgrind"
    echo ""
    echo "  --help|-h: help"
    echo "  --launch-dbus: the test runner by default automatically launches a D-Bus session"
    echo "        depending on a hard-coded list of tests that require it. This flag overwrites"
    echo "        the automatism to always launch a D-Bus session"
    echo "  --no-launch-dbus|-D: prevent launching a D-Bus session"
    echo "  --no-libtool: when running with valgrind, the script tries automatically to"
    echo "        use libtool as necessary. This disables libtool usage" 
    echo "  --make-first|-m: before running the test, make it (only works with autotools build)"
    echo "  --valgrind|-v: run under valgrind"
    echo "  --no-valgrind|-V: disable running under valgrind (overrides NMTST_USE_VALGRIND=1)"
    echo "  -d: set NMTST_DEBUG=d"
    echo "  --test|-t \$TEST: set the test that should be run"
    echo ""
    echo " With \"--test\" and \"--\" you can select the test and which arguments are"
    echo " passed to the test. You can omit these, in which case the first unknown parameter"
    echo " is the test and all other unknown parameters are passed to the test. For example"
    echo "   $0 -m --test src/core/tests/test-core -- -p /general/match-spec/device"
    echo " can also be called as"
    echo "   $0 src/core/tests/test-core -p /general/match-spec/device -m"
    echo ""
    echo "  The following environment variables are honored:"
    echo "    NMTST_USE_VALGRIND=0|1: enable/disable valgrind"
    echo "    NMTST_LIBTOOL=: libtool path (or disable)"
    echo "    NMTST_LAUNCH_DBUS=0|1: whether to lounch a D-Bus session"
    echo "    NMTST_SET_DEBUG=0|1: saet NMTST_DEBUG=d"
    echo ""
    echo " This script is also called by the build system as test wrapper. In that case"
    echo " different, internal command line syntax is used. In that case, environment variables"
    echo " are still honored, so \`NMTST_USE_VALGRIND=1 make check\` works as expected"
}

SCRIPT_PATH="${SCRIPT_PATH:-$(readlink -f "$(dirname "$0")")}"

VALGRIND_ERROR=37

if [ "$1" == "--called-from-make" ]; then
    shift
    CALLED_FROM_MAKE=1
else
    CALLED_FROM_MAKE=0
fi

BUILDDIR=

if [ "$CALLED_FROM_MAKE" == 1 ]; then
    BUILDDIR="$1"
    shift
    if [ -n "$1" ]; then
        NMTST_LIBTOOL=($1 --mode=execute);
    else
        NMTST_LIBTOOL=()
    fi
    shift
    NMTST_VALGRIND_ARG="$1"; shift
    if [[ "$NMTST_VALGRIND_ARG" == no ]]; then
        NMTST_VALGRIND_ARG=
    fi

    if [[ -z "${NMTST_VALGRIND}" ]]; then
        # the valgrind path can be specified via $NMTST_VALGRIND.
        # Otherwise, it can be determined by the configure scripts.
        # Otherwise, it is found in the current $PATH (below).
        if [[ "$NMTST_VALGRIND_ARG" != "" ]]; then
            NMTST_VALGRIND="${NMTST_VALGRIND_ARG}"
        fi
    fi
    if [[ -z "${NMTST_USE_VALGRIND+x}" ]]; then
        # whether to use valgrind can be specified via $NMTST_USE_VALGRIND.
        # Otherwise, it depends on the configure option.
        if [ "$NMTST_VALGRIND_ARG" == "" ]; then
            NMTST_USE_VALGRIND=0
        else
            NMTST_USE_VALGRIND=1
        fi
    fi

    NMTST_SUPPRESSIONS_ARGS="$1"; shift
    if [[ -z "${NMTST_SUPPRESSIONS+x}" ]]; then
        if [[ "$NMTST_SUPPRESSIONS_ARGS" == "" ]]; then
            NMTST_SUPPRESSIONS="$SCRIPT_PATH/../valgrind.suppressions"
        else
            NMTST_SUPPRESSIONS="${NMTST_SUPPRESSIONS_ARGS}"
        fi
    fi


    if [ "$1" = "--launch-dbus" ]; then
        NMTST_LAUNCH_DBUS=1
        shift
    elif [ "$1" = "--launch-dbus=auto" ]; then
        NMTST_LAUNCH_DBUS=
        shift
    else
        NMTST_LAUNCH_DBUS=0
    fi
    TEST="$1"; shift
    NMTST_MAKE_FIRST=0

    TEST_ARGV=("$@")
else
    if [[ -z "${NMTST_USE_VALGRIND+x}" ]]; then
        # by default, disable valgrind checks.
        NMTST_USE_VALGRIND=0
    fi

    if [ -z "${NMTST_LIBTOOL+x}" ]; then
        NMTST_LIBTOOL=(sh "$SCRIPT_PATH/../libtool" "--mode=execute")
    elif [ -z "$NMTST_LIBTOOL" ]; then
        NMTST_LIBTOOL=()
    else
        NMTST_LIBTOOL=("$NMTST_LIBTOOL" "--mode=execute")
    fi
    TEST_ARGV=()
    unset TEST
    while test $# -gt 0; do
        case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        "--launch-dbus")
            NMTST_LAUNCH_DBUS=1
            shift
            ;;
        "--no-launch-dbus"|"-D")
            NMTST_LAUNCH_DBUS=0
            shift
            ;;
        "--no-libtool")
            NMTST_LIBTOOL=()
            shift
            ;;
        --make-first|-m)
            NMTST_MAKE_FIRST=1
            shift
            ;;
        "--valgrind"|-v)
            NMTST_USE_VALGRIND=1
            shift;
            ;;
        "--no-valgrind"|-V)
            NMTST_USE_VALGRIND=0
            shift;
            ;;
        "-d")
            NMTST_SET_DEBUG=1
            shift;
            ;;
        "--test"|-t)
            shift
            TEST="$1"
            shift
            ;;
        "--")
            shift
            if test -z "${TEST+x}"; then
                TEST="$1";
                shift
            fi
            TEST_ARGV+=("$@")
            break
            ;;
        *)
            if test -z "${TEST+x}"; then
                TEST="$1";
            else
                TEST_ARGV+=("$1")
            fi
            shift
            ;;
        esac
    done

    # we support calling the script directly. In this case,
    # only pass the path to the test to run.
    if [[ -z "${NMTST_SUPPRESSIONS+x}" ]]; then
        NMTST_SUPPRESSIONS="$SCRIPT_PATH/../valgrind.suppressions"
    fi

    if [[ -z "$NMTST_BUILDDIR" ]]; then
        if [[ "${NMTST_BUILDDIR-x}" == x ]]; then
            # autodetect
            BUILDDIR="$(readlink -f "$TEST")"
            while [[ -n "$BUILDDIR" ]]; do
                BUILDDIR="$(dirname "$BUILDDIR")"
                [[ "$BUILDDIR" == / ]] && BUILDDIR=
                [[ -z "$BUILDDIR" ]] && break
                [[ -e "$BUILDDIR/src/libnm-client-impl/.libs/libnm.so" ]] && break
                [[ -e "$BUILDDIR/src/libnm-client-impl/libnm.so" ]] && break
            done
        fi
    fi

fi

if [ "$NMTST_SET_DEBUG" == 1 -a -z "${NMTST_DEBUG+x}" ]; then
    export NMTST_DEBUG=d
fi

[ -n "$TEST" ] || die "Missing test name. Specify it on the command line."

if _is_true "$NMTST_MAKE_FIRST" 0; then
    git_dir="$(readlink -f "$(git rev-parse --show-toplevel)")"
    rel_path="$(realpath --relative-to="$git_dir" -m "$TEST" 2>/dev/null)" || die "cannot resolve test-name \"$TEST\". Did you call the script properly?"
    cd "$git_dir"
    make -j5 "$rel_path" || die "make of $TEST failed ($git_dir / $rel_path)"
    cd - 1>/dev/null
fi

[ -x "$TEST" ] || die "Test \"$TEST\" does not exist"
TEST_PATH="$(readlink -f "$(dirname "$TEST")")"
TEST_NAME="${TEST##*/}"

if [ -z "${NMTST_LAUNCH_DBUS}" ]; then
    # autodetect whether to launch D-Bus based on the test path.
    if [[ $TEST_PATH == */src/libnm-client-impl/tests ]]; then
        NMTST_LAUNCH_DBUS=1
    else
        NMTST_LAUNCH_DBUS=0
    fi
fi

# if the user wishes, change first into the directory of the test
if _is_true "$NMTST_CHANGE_DIRECTORY" 0; then
    cd "$TEST_PATH"
    TEST="./$TEST_NAME"
fi

NMTST_DBUS_RUN_SESSION=()
if _is_true "$NMTST_LAUNCH_DBUS"; then
    if ! command -v dbus-run-session &>/dev/null ; then
        eval `dbus-launch --sh-syntax`
        trap "kill $DBUS_SESSION_BUS_PID" EXIT
    else
        NMTST_DBUS_RUN_SESSION=(dbus-run-session --)
    fi
fi

[ -x "$TEST" ] || die "Cannot execute test \"$TEST\""

if [[ -n "$BUILDDIR" ]]; then
    if [[ -d "$BUILDDIR/src/libnm-client-impl" ]]; then
        export GI_TYPELIB_PATH="$BUILDDIR/src/libnm-client-impl/${GI_TYPELIB_PATH:+:$GI_TYPELIB_PATH}"
        if [[ -d "$BUILDDIR/src/libnm-client-impl/.libs" ]]; then
            export LD_LIBRARY_PATH="$BUILDDIR/src/libnm-client-impl/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        else
            export LD_LIBRARY_PATH="$BUILDDIR/src/libnm-client-impl${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        fi
    fi
fi

export ASAN_OPTIONS="$NM_TEST_ASAN_OPTIONS"
export LSAN_OPTIONS="$NM_TEST_LSAN_OPTIONS"
export UBSAN_OPTIONS="$NM_TEST_UBSAN_OPTIONS"
if [ -z "${NM_TEST_ASAN_OPTIONS+x}" ]; then
    ASAN_OPTIONS="fast_unwind_on_malloc=false detect_leaks=1"
fi
if [ -z "${NM_TEST_LSAN_OPTIONS+x}" ]; then
    LSAN_OPTIONS="suppressions=$SCRIPT_PATH/../lsan.suppressions"
fi
if [ -z "${NM_TEST_UBSAN_OPTIONS+x}" ]; then
    UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1"
fi

if ! _is_true "$NMTST_USE_VALGRIND" 0; then
    export NM_TEST_UNDER_VALGRIND=0
    exec "${NMTST_DBUS_RUN_SESSION[@]}" \
    "$TEST" "${TEST_ARGV[@]}"
    die "exec \"$TEST\" failed"
fi

if [[ -z "${NMTST_VALGRIND}" ]]; then
    NMTST_VALGRIND="$(command -v valgrind)" || die "cannot find valgrind binary. Set \$NMTST_VALGRIND"
else
    test -e "${NMTST_VALGRIND}" || die "cannot find valgrind binary from NMTST_VALGRIND=\"${NMTST_VALGRIND}\""
fi

if [[ "${NMTST_SUPPRESSIONS}" != "" ]]; then
    NMTST_SUPPRESSIONS=("--suppressions=$NMTST_SUPPRESSIONS")
else
    NMTST_SUPPRESSIONS=()
fi

LOGFILE="${TEST}.valgrind-log"

export G_SLICE=always-malloc
export G_DEBUG=gc-friendly
export NM_TEST_UNDER_VALGRIND=1
"${NMTST_DBUS_RUN_SESSION[@]}" \
"${NMTST_LIBTOOL[@]}" \
"$NMTST_VALGRIND" \
    --quiet \
    --error-exitcode=$VALGRIND_ERROR \
    --leak-check=full \
    --gen-suppressions=all \
    "${NMTST_SUPPRESSIONS[@]}" \
    --num-callers=100 \
    --log-file="$LOGFILE" \
    "$TEST" \
    "${TEST_ARGV[@]}"
RESULT=$?

test -s "$LOGFILE"
HAS_ERRORS=$?

if [ $RESULT -ne 0 -a $RESULT -ne 77 ]; then
    if [ $HAS_ERRORS -ne 0 ]; then
        rm -f "$LOGFILE"
    elif [ $RESULT -ne $VALGRIND_ERROR ]; then
        # the test (probably) didn't fail due to valgrind.
        echo "The test failed. Also check the valgrind log at '`realpath "$LOGFILE"`'" >&2
    else
        echo "valgrind failed! Check the log at '`realpath "$LOGFILE"`'" >&2
        UNRESOLVED=$(awk -F: '/obj:\// {print $NF}' "$LOGFILE" | sort | uniq)
        if [ -n "$UNRESOLVED" ]; then
            echo Some addresses could not be resolved into symbols. >&2
            echo The errors might get suppressed when you install the debugging symbols. >&2
            if [ -x /usr/bin/dnf ]; then
                echo Hint: dnf debuginfo-install $UNRESOLVED >&2
            elif [ -x /usr/bin/debuginfo-install ]; then
                echo Hint: debuginfo-install $UNRESOLVED >&2
            else
                echo Files without debugging symbols: $UNRESOLVED >&2
            fi
        fi
    fi
    exit $RESULT
fi

if [ $HAS_ERRORS -eq 0 ]; then
    # valgrind doesn't support setns syscall and spams the logfile.
    # hack around it...
    case "$TEST_NAME" in
        'test-address-linux' | \
        'test-cleanup-linux' | \
        'test-config' | \
        'test-l3cfg' | \
        'test-link-linux' | \
        'test-lldp' | \
        'test-nm-client' | \
        'test-platform-general' | \
        'test-remote-settings-client' | \
        'test-route-linux' | \
        'test-secret-agent' | \
        'test-service-providers' | \
        'test-tc-linux' )
            if [ -z "$(sed -e '/^--[0-9]\+-- WARNING: unhandled .* syscall: /,/^--[0-9]\+-- it at http.*\.$/d' "$LOGFILE")" ]; then
                HAS_ERRORS=1
            fi
            ;;
    esac
fi

if [ $HAS_ERRORS -eq 0 ]; then
    # shouldn't actually happen...
    echo "valgrind succeeded, but log is not empty: '`realpath "$LOGFILE"`'" >&2
    exit 1
fi

rm -f "$LOGFILE"

exit $RESULT
