#!/bin/sh

LIBTOOL="$1"; shift
VALGRIND="$1"; shift
SUPPRESSIONS="$1"; shift
VALGRIND_ERROR=37
if [ "$1" = "--launch-dbus" ]; then
    # Spawn DBus
    eval `dbus-launch --sh-syntax`
    trap "kill $DBUS_SESSION_BUS_PID" EXIT
    shift
fi
TEST="$1"

if [ "$NMTST_NO_VALGRIND" != "" ]; then
	"$@"
	exit $?
fi

LOGFILE="valgrind-`echo "$TEST" | tr -cd '[:alpha:]-'`.log"

export G_SLICE=always-malloc
export G_DEBUG=gc-friendly
$LIBTOOL --mode=execute "$VALGRIND" \
	--quiet \
	--error-exitcode=$VALGRIND_ERROR \
	--leak-check=full \
	--gen-suppressions=all \
	--suppressions="$SUPPRESSIONS" \
	--num-callers=100 \
	--log-file="$LOGFILE" \
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
	# shouldn't actually happen...
	echo "valgrind succeeded, but log is not empty: '`realpath "$LOGFILE"`'" >&2
	exit 1
fi

rm -f "$LOGFILE"

exit $RESULT
