#!/bin/bash

set -ex

grep -q '^VERSION=.\(9 (stretch)\|18.04.[0-9]\+ LTS\)' /etc/os-release && IS_DEBIAN_9=1 || IS_DEBIAN_9=0

if [ $IS_DEBIAN_9 = 1 ]; then
    # pam is hosted on this release to the point chfn doesn't work.
    # It's okay on Ubuntu 16.04 and 20.04 though, so keep this version specific.
    #
    # Setting up systemd (237-3ubuntu10.53) ...
    # ...
    # chfn: PAM: System error
    # adduser: `/usr/bin/chfn -f systemd Network Management systemd-network' returned error code 1. Exiting.
    # dpkg: error processing package systemd (--configure):
    #  installed systemd package post-installation script subprocess returned error exit status 1
    # Errors were encountered while processing:
    #  systemd
    ln -sf /bin/true /usr/bin/chfn
fi

DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive NM_INSTALL="apt-get --yes install" bash -x ./contrib/debian/REQUIRED_PACKAGES

dbus-uuidgen --ensure

sed -i 's/^# \(pl_PL.UTF-8 .*\)$/\1/p' /etc/locale.gen || true
locale-gen pl_PL.UTF-8

# Debian 12 and later requires --break-system-packages
pip3 install meson || pip3 install --break-system-packages meson

# iproute2 5.2.0 on debian:sid causes our unit tests to fail.
# Downgrade to a working version. See https://www.spinics.net/lists/netdev/msg584916.html
if dpkg -s iproute2 | grep -q '^Version[:] 5.2.0-1\(ubuntu1\)\?$' ; then
    curl 'http://ftp.debian.org/debian/pool/main/i/iproute2/iproute2_4.20.0-2_amd64.deb' --output /tmp/iproute2_4.20.0-2_amd64.deb
    dpkg -i /tmp/iproute2_4.20.0-2_amd64.deb
fi
