#!/bin/bash

CMD="$1"
shift;

# convert the libtool internal path
resolve_cmd() {
    local C="$1"

    local C2="$(echo "$C" | sed 's#^\(.*/\)\.libs/lt-\([^/]\+\)$#\1\2#')"
    if [[ "$C2" != "$C" && ! -x "$C2" ]]; then
        # such a file does not exist... back to $C
        C2="$C"
    fi
    echo "$C2"
}

if [[ $UID == 0 ]]; then
    # we are already root. Execute directly.
    exec "$(resolve_cmd "$CMD")" "$@"
elif [[ "$NMTST_SUDO_NO_CALL_SELF" != "" ]]; then
    # when setting $NMTST_SUDO_NO_CALL_SELF, pass the (resolved) command
    # directly to sudo.
    exec sudo "$(resolve_cmd "$CMD")" "$@"
else
    # by default, call self again with sudo.
    exec sudo -E "$0" "$CMD" "$@"
fi

