#!/bin/bash

CMD="$1"
shift;

if [[ $UID == 0 ]]; then
    # we are already root. Execute directly.
    exec "$CMD" "$@"
elif [[ "$NMTST_SUDO_NO_CALL_SELF" != "" ]]; then
    # when setting $NMTST_SUDO_NO_CALL_SELF, pass the (resolved) command
    # directly to sudo.
    exec sudo "$CMD" "$@"
else
    # by default, call self again with sudo.
    exec sudo -E "$0" "$CMD" "$@"
fi

