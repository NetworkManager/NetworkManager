#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

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
echo "+ Setting up submodules"
git submodule init
git submodule update

gtkdocize || exit 1
autopoint --force
AUTOPOINT='intltoolize --automake --copy' autoreconf --force --install --verbose

cd $olddir
if test -z "$NOCONFIGURE"; then
	$srcdir/configure --enable-maintainer-mode "$@"
fi
