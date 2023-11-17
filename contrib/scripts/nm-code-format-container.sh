#!/bin/bash

set -e

die() {
    echo "$@" >&2
    exit 1
}

DIR="$(realpath "$(dirname "$0")/../../")"
cd "$DIR"

# The correct clang-format version is the one from the Fedora version used in our
# gitlab-ci pipeline. Parse it from ".gitlab-ci/config.yml".
FEDORA_VERSION="$(sed '/^    tier: 1/,/^  - name/!d' .gitlab-ci/config.yml | sed -n "s/^      - '\([0-9]\+\)'$/\1/p" | sed -n 1p)"

test -n "$FEDORA_VERSION" || die "Could not detect the Fedora version in .gitlab-ci/config.yml"

IMAGENAME="nm-code-format:f$FEDORA_VERSION"

ARGS=( "$@" )

if ! podman image exists "$IMAGENAME" ; then
    echo "Building image \"$IMAGENAME\"..."
    podman build \
        --squash-all \
        --tag "$IMAGENAME" \
        -f <(cat <<EOF
FROM fedora:$FEDORA_VERSION
RUN dnf upgrade -y
RUN dnf install -y git /usr/bin/clang-format
EOF
)
fi

CMD=( ./contrib/scripts/nm-code-format.sh "${ARGS[@]}" )

podman run \
    --rm \
    --name "nm-code-format-f$FEDORA_VERSION" \
    -v "$DIR:/tmp/NetworkManager:Z" \
    -w /tmp/NetworkManager \
    -e "_NM_CODE_FORMAT_CONTAINER=$IMAGENAME" \
    -ti \
    "$IMAGENAME" \
    "${CMD[@]}"
