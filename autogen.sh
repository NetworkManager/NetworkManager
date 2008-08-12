#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.
REQUIRED_AUTOMAKE_VERSION=1.7
PKG_NAME=NetworkManager

(test -f $srcdir/configure.in \
  && test -f $srcdir/src/NetworkManager.c) || {
    echo -n "**Error**: Directory "\`$srcdir\'" does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
}

(cd $srcdir;
    gtkdocize || exit 1
    autoreconf --install --symlink &&
    intltoolize --force &&
    autoreconf &&
    ./configure --enable-maintainer-mode $@
)

