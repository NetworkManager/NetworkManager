#!/bin/bash

set -x
echo ===================================
env

echo ===================================
NOCONFIGURE=yes ./orig-autogen.sh

echo ===================================
./configure \
PYTHON="${PYTHON}" \
--enable-maintainer-mode \
--enable-more-warnings=error \
--prefix=/opt/test \
--sysconfdir=/etc \
--enable-gtk-doc \
--enable-more-asserts \
--with-more-asserts=100 \
--enable-more-logging \
--enable-compile-warnings=yes\
--with-valgrind=no \
--enable-concheck \
--enable-ifcfg-rh \
--enable-ifcfg-suse \
--enable-ifupdown \
--enable-ifnet \
--enable-vala=yes \
--enable-polkit=yes \
--with-nmtui=yes \
--with-modem-manager-1 \
--with-suspend-resume=systemd \
--enable-teamdctl=yes \
--enable-tests=root \
--with-netconfig=/path/does/not/exist/netconfig \
--with-resolvconf=/path/does/not/exist/resolvconf \
--with-crypto=nss \
--with-session-tracking=systemd \
--with-consolekit=yes \
--with-systemd-logind=yes \
--with-consolekit=yes

make -j20
make check -k

echo ===================================
make check -k

echo ===================================
src/libnm-client-impl/tests/test-nm-client

echo ===================================
src/libnm-client-impl/tests/test-nm-client -p /libnm/activate-virtual


echo ===================================
env -i XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR src/libnm-client-impl/tests/test-nm-client

echo ===================================
env -i XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR src/libnm-client-impl/tests/test-nm-client -p /libnm/activate-virtual


echo ===================================
dnf -y install strace

echo ===================================
strace -s4096 -f -otest1 src/libnm-client-impl/tests/test-nm-client

echo ===================================
strace -s4096 -f -otest2 src/libnm-client-impl/tests/test-nm-client -p /libnm/activate-virtual

echo ===================================
strace -s4096 -f -otest3 env -i XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR src/libnm-client-impl/tests/test-nm-client

echo ===================================
strace -s4096 -f -otest4 env -i XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR src/libnm-client-impl/tests/test-nm-client -p /libnm/activate-virtual


grep '' test?

exit 1
