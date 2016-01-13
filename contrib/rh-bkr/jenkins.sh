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
# GIT_TEST_BRANCH=

# Trigger from remote:
# TOKEN_NAME= // secret
# URL="https://desktopqe-jenkins.rhev-ci-vms.eng.rdu2.redhat.com/job/NetworkManager-upstream/buildWithParameters?token=$TOKEN_NAME&cause=$CAUSE&ARGS=..."

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

if [ -n "$GIT_TEST_BRANCH" -a "$GIT_TEST_BRANCH" != "--" ]; then
	GIT_TEST_BRANCH=(--var "GIT_TEST_BRANCH=$GIT_TEST_BRANCH")
else
	GIT_TEST_BRANCH=()
fi

if [ "$ARCH" == "<random>" ]; then
	ARCH=(x86_64 ppc64 ppc64le s390x aarch64)
	ARCH=${ARCH[$(($RANDOM % ${#ARCH[@]}))]}
fi

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
    --var "DISTRO_TAG=$DISTRO_TAG" \
    --var "DISTRO_NAME=$DISTRO_NAME" \
    "${PROFILE[@]}" \
    "${HOSTTYPE[@]}" \
    --var "TESTS=$TESTS" \
    "${GIT_TEST_BRANCH[@]}" \
    --bkr-write-job-id 'beaker_job_id' \
    --bkr-wait-completion \
    --bkr-job-results 'results.xml' \
    --no-test \
    "${_ARGS[@]}"

