#!/bin/sh

LIBTOOL="$1"; shift
VALGRIND="$1"; shift
SUPPRESSIONS="$1"; shift
TEST="$1"; shift

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

if [ $RESULT -ne 0 ]; then
	echo "Don't forget to check the valgrind log at '$LOGFILE'." >&2
fi

exit $RESULT
