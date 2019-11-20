#!/bin/bash

srcdir=${1:-.}
ret=0

get_supported_options()
{
    awk '/START OPTION LIST/{flag=1;next}/END OPTION LIST/{flag=0}flag' "$srcdir/src/nm-config.c" |
	grep -o 'NM_CONFIG_KEYFILE_KEY_\w*'
}

get_missing_options()
{
    grep -v '/\* check-config-options skip \*/' "$srcdir/src/nm-config.h" |
	grep -o 'NM_CONFIG_KEYFILE_KEY_\w*' |
	grep -v -Fx -f <(get_supported_options)
}

get_src_con_defaults()
{
    sed -ne 's/.*\<NM_CON_DEFAULT\s*("\([^"]*\)").*/\1/p' $(find "$srcdir/src/" -name \*.c ! -name test\*.c)
    sed -ne 's/.*\<NM_CON_DEFAULT_NOP\s*("\([^"]*\)").*/\1/p' $(find "$srcdir/src/" -name \*.c ! -name test\*.c)
}

get_man_con_defaults()
{
    awk '/start connection defaults/{flag=1;next}/end connection defaults/{flag=0}flag' "$srcdir/man/NetworkManager.conf.xml" |
	sed -ne 's#.*<varname>\([^<]*\)</varname>.*#\1#p'
}

get_missing_con_defaults()
{
    get_src_con_defaults | grep -v -Fx -f <(get_man_con_defaults)
}

get_missing_con_defaults2()
{
    get_man_con_defaults | grep -v -Fx -f <(get_src_con_defaults)
}

missing=$(get_missing_options)

if [ -n "$missing" ]; then
    echo "***"
    echo "*** Error: the following configuration options are defined but not present in the list of supported options"
    echo "***"
    echo "$missing"
    echo
    ret=1
fi

missing_con_defaults=$(get_missing_con_defaults)
if [ -n "$missing_con_defaults" ]; then
    echo "***"
    echo "*** Error: the following connection defaults are present in source files but not in the NetworkManager.conf man page:"
    echo "***"
    echo "$missing_con_defaults"
    echo
    ret=1
fi

missing_con_defaults2=$(get_missing_con_defaults2)
if [ -n "$missing_con_defaults2" ]; then
    echo "***"
    echo "*** Error: the following connection defaults are present in the NetworkManager.conf man page but not in source files:"
    echo "***"
    echo "$missing_con_defaults2"
    echo
    ret=1
fi

exit $ret
