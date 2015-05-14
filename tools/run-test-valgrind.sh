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
TEST="$1"; shift

if [ "$NMTST_NO_VALGRIND" != "" ]; then
	"$TEST"
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
	--log-file="$LOGFILE" \
	"$TEST"
RESULT=$?

if [ $RESULT -eq 0 -a "$(wc -c "$LOGFILE" | awk '{print$1}')" -ne 0 ]; then
	echo "valgrind succeeded, but log is not empty: $LOGFILE"
	exit 1
fi

if [ $RESULT -ne 0 -a $RESULT -ne 77 ]; then
	echo "Don't forget to check the valgrind log at '`realpath $LOGFILE`'." >&2
fi

exit $RESULT
