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

# Whether to use valgrind can be controlled via command line
# variables $NMTST_USE_VALGRIND set to true/false
#
# When --called-from-makefile, the variable has only
# effect when `./configure --with-valgrind`. Otherwise,
# valgrind is never used during `make check`.
# When `./configure --with-valgrind`, valgrind is used
# unless it's disabled via environment variable.
#
# When called directly, the arguments -v|-V overwrite the
# setting from the environment variable.
# When neither specified via command line or environemt
# variable, default to "false".
if [[ -z "${NMTST_USE_VALGRIND+x}" ]]; then
    if [ "$CALLED_FROM_MAKE" == 1 ]; then
        NMTST_USE_VALGRIND=1
    else
        NMTST_USE_VALGRIND=0
    fi
fi

if [ "$CALLED_FROM_MAKE" == 1 ]; then
    NMTST_LIBTOOL=($1 --mode=execute); shift
    NMTST_VALGRIND="$1"; shift
    if [[ "$NMTST_VALGRIND" == no ]]; then
        NMTST_USE_VALGRIND=0
        NMTST_VALGRIND=
    fi
    SUPPRESSIONS="$1"; shift
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
    if [ -n "${NMTST_LIBTOOL-:x}" ]; then
        NMTST_LIBTOOL=(sh "$SCRIPT_PATH/../libtool" --mode=execute)
    elif [ -n "${NMTST_LIBTOOL-x}" ]; then
        NMTST_LIBTOOL=()
    else
        NMTST_LIBTOOL=($NMTST_LIBTOOL --mode=execute)
    fi
    for a in "$@"; do
        case "$a" in
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
    TEST="$1"; shift
    if [ "$SUPPRESSIONS" == "" ]; then
        SUPPRESSIONS="$SCRIPT_PATH/../valgrind.suppressions"
    fi

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

if _is_true "$NMTST_MAKE_FIRST" 0; then
    git_dir="$(readlink -f "$(git rev-parse --show-toplevel)")"
    rel_path="${TEST_PATH/#$(printf '%s/' "$git_dir")}/$TEST_NAME"
    cd "$git_dir"
    make -j5 "$rel_path" || die "make of $TEST failed ($git_dir / $rel_path)"
    cd - 1>/dev/null
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
    --suppressions="$SUPPRESSIONS" \
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
            echo The errors might get suppressed when you install the debuging symbols. >&2
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
    if [ "$TEST_NAME" = 'test-link-linux' -a -z "$(sed -e '/^--[0-9]\+-- WARNING: unhandled .* syscall: /,/^--[0-9]\+-- it at http.*\.$/d' "$LOGFILE")" ]; then
        HAS_ERRORS=1
    fi
fi

if [ $HAS_ERRORS -eq 0 ]; then
    # shouldn't actually happen...
    echo "valgrind succeeded, but log is not empty: '`realpath "$LOGFILE"`'" >&2
    exit 1
fi

rm -f "$LOGFILE"

exit $RESULT
