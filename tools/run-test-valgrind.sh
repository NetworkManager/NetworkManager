#!/bin/sh

LIBTOOL="$1"; shift
VALGRIND="$1"; shift
SUPPRESSIONS="$1"; shift
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
	--error-exitcode=1 \
	--leak-check=full \
	--gen-suppressions=all \
	--suppressions="$SUPPRESSIONS" \
	--num-callers=100 \
	--log-file="$LOGFILE" \
	"$@"
RESULT=$?

if [ $RESULT -eq 0 -a "$(wc -c "$LOGFILE" | awk '{print$1}')" -ne 0 ]; then
	echo "valgrind succeeded, but log is not empty: $LOGFILE"
	exit 1
fi

if [ $RESULT -ne 0 -a $RESULT -ne 77 ]; then
	echo "valgrind failed! Check the log at '`realpath $LOGFILE`'." >&2
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
	exit $RESULT
fi

find -name "$LOGFILE" -size 0 -delete

exit $RESULT
