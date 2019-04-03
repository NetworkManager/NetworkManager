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

else
    if [[ -z "${NMTST_USE_VALGRIND+x}" ]]; then
        # by default, disable valgrind checks.
        NMTST_USE_VALGRIND=0
    fi

    if [ -n "${NMTST_LIBTOOL-:x}" ]; then
        NMTST_LIBTOOL=(sh "$SCRIPT_PATH/../libtool" --mode=execute)
    elif [ -n "${NMTST_LIBTOOL-x}" ]; then
        NMTST_LIBTOOL=()
    else
        NMTST_LIBTOOL=($NMTST_LIBTOOL --mode=execute)
    fi
    unset TEST
    while test $# -gt 0; do
        case "$1" in
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
            break
            ;;
        *)
            break
            ;;
        esac
    done

    # we support calling the script directly. In this case,
    # only pass the path to the test to run.
    if test -z "${TEST+x}"; then
        TEST="$1"; shift
    fi
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
                [[ -e "$BUILDDIR/libnm/.libs/libnm.so" ]] && break
                [[ -e "$BUILDDIR/libnm/libnm.so" ]] && break
            done
        fi
    fi

fi

if [ "$NMTST_SET_DEBUG" == 1 -a -z "${NMTST_DEBUG+x}" ]; then
    export NMTST_DEBUG=d
fi

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
    if [[ $TEST_PATH == */libnm/tests || $TEST_PATH == */libnm-glib/tests ]]; then
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
    if ! which dbus-run-session &>/dev/null ; then
        eval `dbus-launch --sh-syntax`
        trap "kill $DBUS_SESSION_BUS_PID" EXIT
    else
        NMTST_DBUS_RUN_SESSION=(dbus-run-session --)
    fi
fi

[ -x "$TEST" ] || die "Cannot execute test \"$TEST\""

if [[ -n "$BUILDDIR" ]]; then
    if [[ -d "$BUILDDIR/libnm" ]]; then
        export GI_TYPELIB_PATH="$BUILDDIR/libnm/${GI_TYPELIB_PATH:+:$GI_TYPELIB_PATH}"
        if [[ -d "$BUILDDIR/libnm/.libs" ]]; then
            export LD_LIBRARY_PATH="$BUILDDIR/libnm/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        else
            export LD_LIBRARY_PATH="$BUILDDIR/libnm${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        fi
    fi
fi

if ! _is_true "$NMTST_USE_VALGRIND" 0; then
    "${NMTST_DBUS_RUN_SESSION[@]}" \
    "$TEST" "$@"
    exit $?
fi

if [[ -z "${NMTST_VALGRIND}" ]]; then
    NMTST_VALGRIND=`which valgrind` || die "cannot find valgrind binary. Set \$NMTST_VALGRIND"
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
    "$@"
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
    if [ "$TEST_NAME" = 'test-link-linux' -o \
         "$TEST_NAME" = 'test-acd' ]; then
        if [ -z "$(sed -e '/^--[0-9]\+-- WARNING: unhandled .* syscall: /,/^--[0-9]\+-- it at http.*\.$/d' "$LOGFILE")" ]; then
            HAS_ERRORS=1
        fi
    fi
fi

if [ $HAS_ERRORS -eq 0 ]; then
    # shouldn't actually happen...
    echo "valgrind succeeded, but log is not empty: '`realpath "$LOGFILE"`'" >&2
    exit 1
fi

rm -f "$LOGFILE"

exit $RESULT
