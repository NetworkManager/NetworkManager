#!/bin/bash

die() {
    echo "$@"
    exit 5
}

SCRIPT_PATH="${SCRIPT_PATH:-$(readlink -f "$(dirname "$0")")}"

VALGRIND_ERROR=37
if [ "$1" == "--called-from-make" ]; then
    shift
    NMTST_LIBTOOL=($1 --mode=execute); shift
    NMTST_VALGRIND="$1"; shift
    SUPPRESSIONS="$1"; shift
    if [ "$1" = "--launch-dbus" ]; then
        NMTST_LAUNCH_DBUS=yes
        shift
    else
        NMTST_LAUNCH_DBUS=no
    fi
    TEST="$1"; shift
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
            NMTST_LAUNCH_DBUS=yes
            shift
            ;;
        "--no-launch-dbus"|"-D")
            NMTST_LAUNCH_DBUS=no
            shift
            ;;
        "--no-libtool")
            NMTST_LIBTOOL=()
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
    TEST="$1"; shift
    NMTST_VALGRIND="${NMTST_VALGRIND:-valgrind}"
    if [ "$SUPPRESSIONS" == "" ]; then
        SUPPRESSIONS="$SCRIPT_PATH/../valgrind.suppressions"
    fi

    [ -x "$TEST" ] || die "Test \"$TEST\" does not exist"

    TEST_PATH="$(readlink -f "$(dirname "$TEST")")"

    if [ -n "${NMTST_LAUNCH_DBUS-x}" ]; then
        # autodetect whether to launch D-Bus based on the test path.
        if [[ $TEST_PATH == */libnm/tests || $TEST_PATH == */libnm-glib/tests ]]; then
            NMTST_LAUNCH_DBUS=yes
        else
            NMTST_LAUNCH_DBUS=no
        fi
    fi

    # some tests require you to cd into the base directory.
    # do that.
    if [ "$NMTST_VALGRIND_NO_CD" == "" ]; then
        cd "$TEST_PATH"
        TEST="./$(basename "$TEST")"
    fi
fi

NMTST_DBUS_RUN_SESSION=()
if [ "$NMTST_LAUNCH_DBUS" == "yes" ]; then
    if ! which dbus-run-session &>/dev/null ; then
        eval `dbus-launch --sh-syntax`
        trap "kill $DBUS_SESSION_BUS_PID" EXIT
    else
        NMTST_DBUS_RUN_SESSION=(dbus-run-session --)
    fi
fi

if [ "$NMTST_NO_VALGRIND" != "" ]; then
	"$TEST" "$@"
	exit $?
fi

LOGFILE="${TEST}.valgrind-log"

export G_SLICE=always-malloc
export G_DEBUG=gc-friendly
"${NMTST_DBUS_RUN_SESSION[@]}" \
"${NMTST_LIBTOOL[@]}" "$NMTST_VALGRIND" \
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
	if [ "$(basename "$TEST")" = 'test-link-linux' -a -z "$(sed -e '/^--[0-9]\+-- WARNING: unhandled .* syscall: /,/^--[0-9]\+-- it at http.*\.$/d' "$LOGFILE")" ]; then
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
