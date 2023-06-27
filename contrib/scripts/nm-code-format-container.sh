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

PODNAME="nm-code-format-f$FEDORA_VERSION"

RENEW=0
for a; do
    case "$a" in
        -f)
            RENEW=1
            ;;
        *)
            die "invalid argument \"$a\""
            ;;
    esac
done

set -x

if [ "$RENEW" == 1 ]; then
    if podman container exists "$PODNAME" ; then
        podman rm "$PODNAME"
    fi
fi

if ! podman container exists "$PODNAME" ; then
    podman run \
        --name="$PODNAME" \
        -v "$DIR:/tmp/NetworkManager:Z" \
        -w /tmp/NetworkManager \
        "fedora:$FEDORA_VERSION" \
        /bin/bash -c 'dnf upgrade -y && dnf install -y git /usr/bin/clang-format && ./contrib/scripts/nm-code-format.sh -i'
    exit 0
fi

podman start -a "$PODNAME"
