#!/bin/bash

# Runs the "test-python.sh" test, setting proper environment variables
# for the build tree.
#
# - the first three arguments are the BUILDDIR, SRCDIR and PYTHON paths.
#   The following arguments are passed on to "test-python.sh".
#
# - you can use "--" to separate the extra arguments.
#
# The full format is
#
#   $ src/tests/client/test-client.sh "$BUILDDIR" "$SRCDIR" "$PYTHON" -- "${EXTRA[@]}"
#
# - "$BUILDDIR" "$SRCDIR" and "$PYTHON" can be set to "", to fallback
#   to a default.
#
# The safe way to call it is thus
#
#     $ src/tests/client/test-client.sh "" "" "" -- "${EXTRA[@]}"
#
# but for brevity, you can also call
#
#     $ src/tests/client/test-client.sh -- "${EXTRA[@]}"
#
# if (and only if) "${EXTRA[@]}" does not contain "--".

set -e

die() {
    printf '%s\n' "$@"
    exit 1
}

if [ "$4" = "--" ] ; then
    ARGS=("${@:1:3}")
    EXTRA=("${@:5}")
elif [ "$3" = "--" ]; then
    ARGS=("${@:1:2}")
    EXTRA=("${@:4}")
elif [ "$2" = "--" ]; then
    ARGS=("${@:1:1}")
    EXTRA=("${@:3}")
elif [ "$1" = "--" ]; then
    ARGS=()
    EXTRA=("${@:2}")
else
    ARGS=("${@:1:3}")
    EXTRA=("${@:4}")
fi

if [ "${ARGS[1]}" != "" ]; then
    SRCDIR="$(realpath "${ARGS[1]}")"
else
    SRCDIR="$(realpath "$(dirname "$BASH_SOURCE")/../../..")"
fi

if [ "${ARGS[0]}" != "" ]; then
    BUILDDIR="$(realpath "${ARGS[0]}")"
elif test -d "$SRCDIR/build" ; then
    BUILDDIR="$(realpath "$SRCDIR/build")"
else
    BUILDDIR="$SRCDIR"
fi

if [ "${ARGS[2]}" != "" ]; then
    PYTHON="${ARGS[2]}"
elif [ "$PYTHON" == "" ]; then
    PYTHON="$(command -v python)" || die "python not found?"
fi

test -d "$BUILDDIR" || die "BUILDDIR \"$BUILDDIR\" does not exist?"
test -d "$SRCDIR" || die "SRCDIR \"$SRCDIR\" does not exist?"
test -f "$BUILDDIR/src/nmcli/nmcli" || die "\"$BUILDDIR/src/nmcli/nmcli\" does not exist?"

if test -f "$BUILDDIR/src/libnm-client-impl/.libs/libnm.so" ; then
    LIBDIR="$BUILDDIR/src/libnm-client-impl/.libs"
elif test -f "$BUILDDIR/src/libnm-client-impl/libnm.so" ; then
    LIBDIR="$BUILDDIR/src/libnm-client-impl"
else
    die "libnm.so does not exist under expected paths in \"$BUILDDIR/src/libnm-client-impl/{.,.libs}/\""
fi

mkdir -p "$BUILDDIR/src/tests/client/" || die "failure to create build output directory \"$BUILDDIR/src/tests/client/\""

export NM_TEST_CLIENT_NMCLI_PATH="$BUILDDIR/src/nmcli/nmcli"
export GI_TYPELIB_PATH="$BUILDDIR/src/libnm-client-impl${GI_TYPELIB_PATH:+:$GI_TYPELIB_PATH}"
export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export NM_TEST_CLIENT_BUILDDIR="$BUILDDIR"

# Run nmcli at least once. With libtool, nmcli is a shell script and with LTO
# this seems to perform some slow setup during the first run. If we do that
# during the test, it will timeout and fail.
"$NM_TEST_CLIENT_NMCLI_PATH" --version &>/dev/null

# we first collect all the output in "test-client.log" and print it at once
# afterwards. The only reason is that when you run with `make -j` that the
# test output is grouped together.

r="ok"
"$PYTHON" "$SRCDIR/src/tests/client/test-client.py" -v "${EXTRA[@]}" &> "$BUILDDIR/src/tests/client/test-client.log" || r=fail

cat "$BUILDDIR/src/tests/client/test-client.log"

test "$r" = ok || die "test-client.py failed!!"
