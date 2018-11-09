#!/bin/bash

srcdir=${1:-.}

get_supported_options()
{
    awk '/START OPTION LIST/{flag=1;next}/END OPTION LIST/{flag=0}flag' "$srcdir/src/nm-config.c" |
	grep -o 'NM_CONFIG_KEYFILE_KEY_\w*'
}

get_missing()
{
    grep -v '/\* check-config-options skip \*/' "$srcdir/src/nm-config.h" |
	grep -o 'NM_CONFIG_KEYFILE_KEY_\w*' |
	grep -v -Fx -f <(get_supported_options)
}

missing=$(get_missing)

if [ -n "$missing" ]; then
    echo "***"
    echo "*** Error: the following configuration options are defined but not present in the list of supported options"
    echo "***"
    echo "$missing"
    exit 1
fi

exit 0
