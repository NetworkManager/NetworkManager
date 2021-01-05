#!/bin/bash

set -ex

IS_UBUNTU_1604=0
grep -q '^VERSION=.16.04.[0-9]\+ LTS' /etc/os-release && IS_UBUNTU_1604=1


DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive NM_INSTALL="apt-get -qq install -y" ./contrib/debian/REQUIRED_PACKAGES

dbus-uuidgen --ensure

sed -i 's/^# \(pl_PL.UTF-8 .*\)$/\1/p' /etc/locale.gen || true
locale-gen pl_PL.UTF-8

if [ $IS_UBUNTU_1604 = 1 ]; then
    pip3 install meson==0.53.2
    contrib/scripts/nm-ci-install-valgrind-in-ubuntu1604.sh
else
    pip3 install meson
fi

# iproute2 5.2.0 on debian:sid causes our unit tests to fail.
# Downgrade to a working version. See https://www.spinics.net/lists/netdev/msg584916.html
if dpkg -s iproute2 | grep -q '^Version[:] 5.2.0-1\(ubuntu1\)\?$' ; then
    curl 'http://ftp.debian.org/debian/pool/main/i/iproute2/iproute2_4.20.0-2_amd64.deb' --output /tmp/iproute2_4.20.0-2_amd64.deb
    dpkg -i /tmp/iproute2_4.20.0-2_amd64.deb
fi
