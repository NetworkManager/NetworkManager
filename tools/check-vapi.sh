#!/bin/bash

set -e

die() {
    printf "%s\n" "$*" >&2
    exit 1
}

GENERATED_VAPI="$1"
test -n "$GENERATED_VAPI" || die "usage: $(basename "$0") <path-to-generated-libnm.vapi>"
test -f "$GENERATED_VAPI" || die "generated vapi '$GENERATED_VAPI' not found"

# Fail if any NM_SETTING_*/NM_DEVICE_* constant ended up at namespace
# level (a single leading tab) instead of inside its class: that means
# a setting or device is missing a rule in vapi/NM-1.0.metadata.
orphans="$(grep -nP '^\tpublic const string (SETTING|DEVICE)_' -- "$GENERATED_VAPI" || true)"
test -z "$orphans" || die "constants leaked into the NM namespace in \"$GENERATED_VAPI\"
(add a rule to vapi/NM-1.0.metadata for the setting/device that owns them):
$orphans"
