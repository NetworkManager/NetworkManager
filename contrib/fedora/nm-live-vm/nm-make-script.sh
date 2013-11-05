#!/bin/bash

set -vx

die() {
    echo "$@" >&2
    exit 1
}

COMMIT=${1:-origin/master}

URL="${2:-"git://anongit.freedesktop.org/NetworkManager/NetworkManager"}"

passwd -d root
test -d /NetworkManager || (
    git init /NetworkManager
    cd /NetworkManager

    # check if there is a local git repository and fetch from it first (should be faster)
    test -d "/NetworkManager-local.git" && (
        git remote add local "/NetworkManager-local.git"
        git fetch local
        git remote remove local
        rm -rf "/NetworkManager-local.git"
    )
    git remote add origin "$URL"
)
cd /NetworkManager/ || exit 1
git fetch origin || die "Could not fetch $URL"
git checkout -f "$COMMIT" || exit 1
./autogen.sh --prefix=/usr --exec-prefix=/usr --libdir=/usr/lib --sysconfdir=/etc --localstatedir=/var --enable-gtk-doc || exit 1
make || exit 1
#make check || exit 1
make install || exit 1
echo -e "[main]\nplugins=ifcfg-rh\n" > /etc/NetworkManager/NetworkManager.conf
/bin/systemctl enable NetworkManager.service || exit 1
