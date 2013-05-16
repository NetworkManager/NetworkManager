#!/bin/bash

BRANCH=${1:-"master"}
COMMIT=origin/$BRANCH

cd /
passwd -d root
test -d NetworkManager || git clone git://anongit.freedesktop.org/NetworkManager/NetworkManager || exit 1
cd NetworkManager/ || exit 1
git fetch
git checkout -f $COMMIT || exit 1
./autogen.sh --prefix=/ --exec-prefix=/usr --libdir=/usr/lib --datadir=/usr/share --mandir=/usr/share/man --enable-gtk-doc || exit 1
make || exit 1
#make check || exit 1
make install || exit 1
echo -e "[main]\nplugins=ifcfg-rh\n" > /etc/NetworkManager/NetworkManager.conf
/bin/systemctl enable NetworkManager.service || exit 1
