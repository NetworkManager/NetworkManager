#!/bin/sh

LC_ALL=C
export LC_ALL

stat=0
so=$1
def=$2

# Have to prefix with a tab and suffix with a ';' to match .ver file format
get_syms='nm "$so" | grep "^[[:xdigit:]]\+ T " | sed "s/^[[:xdigit:]]\+ T //" | sed "s/^/\t/" | sed "s/$/;/"'

echo $so: checking exported symbols against $def

{
	echo "{"
	echo "global:"
	eval $get_syms | sort -u
	echo "local:"
	echo "	*;"
	echo "};"
} | diff -u "$def" - >&2 || stat=1

exit $stat

