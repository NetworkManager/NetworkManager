#!/bin/sh
# Run this to generate all the initial makefiles, etc.

set -e

srcdir=`dirname $0`
if test -z "$srcdir"; then
    srcdir=.
fi

olddir=`pwd`

REQUIRED_AUTOMAKE_VERSION=1.9
PKG_NAME=NetworkManager

(test -f $srcdir/configure.ac \
  && test -f $srcdir/src/core/main.c) || {
    printf "**Error**: Directory "\`$srcdir\'" does not look like the" >&2
    echo " top-level $PKG_NAME directory" >&2
    exit 1
}

cd $srcdir

aclocal --install || exit 1
gtkdocize --copy || exit 1
autoreconf --verbose --force --install || exit 1

cd $olddir
if test -z "$NOCONFIGURE"; then
    exec $srcdir/configure --enable-maintainer-mode --enable-more-warnings=error --enable-gtk-doc --enable-introspection "$@"
fi
