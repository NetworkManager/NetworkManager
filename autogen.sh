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
  && test -f $srcdir/src/main.c) || {
    echo -n "**Error**: Directory "\`$srcdir\'" does not look like the"
    echo " top-level $PKG_NAME directory"
    exit 1
}

cd $srcdir

# Fetch submodules if needed
if test -d $srcdir/.git; then
    echo "+ Setting up submodules"
    git submodule init
    git submodule update
fi

gtkdocize
autopoint --force
AUTOPOINT='intltoolize --automake --copy' autoreconf --force --install --verbose

cd $olddir
if test -z "$NOCONFIGURE"; then
	exec $srcdir/configure --enable-maintainer-mode "$@"
fi
