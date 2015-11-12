#!/bin/bash

set -e
set -x

DIR="$(dirname "$(readlink -f "$0")")"

# We allow and expect the following environment variable
# set by jenkins:
# ARCH=       // one of x86_64, ppc64, ppc64le, s390x, aarch64
# RPM_URLS=   // space separated list of --rpm arguments
# BUILD_ID=   // if non-empty, build NetworkManager from source and install it
# RESERVE=    // number of seconds to reserve the system (or empty)
# SELINUX=    // if set to 'false', boot with selinux=0
# PROFILE=
# HOSTYPE=
# TESTS=
# ARGS=

RPM=()
for r in $RPM_URLS; do
	RPM+=(--rpm "$r")
done

if [ -n "$BUILD_ID" ]; then
	BUILD_ID=(--build-id "$BUILD_ID")
else
	BUILD_ID=()
fi

if [ -n "$PROFILE" -a "$PROFILE" != "--" ]; then
	PROFILE=(--profile "$PROFILE")
else
	PROFILE=()
fi

if [ -n "$HOSTTYPE" -a "$HOSTTYPE" != "--" ]; then
	HOSTTYPE=(--hosttype "$HOSTTYPE")
else
	HOSTTYPE=()
fi

_ARGS=()
for r in $ARGS; do
	_ARGS+=("$r")
done

export WHITEBOARD="$BUILD_URL"

python -u \
    "$DIR"/bkr.py submit -v -v \
    -J \
    --var "WHITEBOARD=Test NetworkManager $BUILD_URL" \
    "${RPM[@]}" \
    "${BUILD_ID[@]}" \
    --var "ARCH=$ARCH" \
    --var "RESERVE=$RESERVE" \
    --var "SELINUX=$SELINUX" \
    "${PROFILE[@]}" \
    "${HOSTTYPE[@]}" \
    --var "TESTS=$TESTS" \
    --bkr-write-job-id 'beaker_job_id' \
    --bkr-wait-completion \
    --bkr-job-results 'results.txt' \
    --no-test \
    "${_ARGS[@]}"

