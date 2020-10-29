#!/bin/bash

date '+%Y%m%d-%H%M%S'; DEBIAN_FRONTEND=noninteractive apt-get update
date '+%Y%m%d-%H%M%S'; DEBIAN_FRONTEND=noninteractive NM_INSTALL="apt-get -qq install -y" ./contrib/debian/REQUIRED_PACKAGES
date '+%Y%m%d-%H%M%S'; dbus-uuidgen --ensure
date '+%Y%m%d-%H%M%S'; sed -i 's/^# \(pl_PL.UTF-8 .*\)$/\1/p' /etc/locale.gen ; true
date '+%Y%m%d-%H%M%S'; locale-gen pl_PL.UTF-8
date '+%Y%m%d-%H%M%S'; grep -q "VERSION=.16.04.[0-9]\+ LTS" /etc/os-release && pip3 install meson==0.53.2
date '+%Y%m%d-%H%M%S'; grep -q "VERSION=.16.04.[0-9]\+ LTS" /etc/os-release || pip3 install meson
date '+%Y%m%d-%H%M%S'; contrib/scripts/nm-ci-install-valgrind-in-ubuntu1604.sh

# iproute2 5.2.0 on debian:sid causes our unit tests to fail.
# Downgrade to a working version. See https://www.spinics.net/lists/netdev/msg584916.html
date '+%Y%m%d-%H%M%S'; ! ( dpkg -s iproute2 | grep -q '^Version[:] 5.2.0-1\(ubuntu1\)\?$' ) || (curl 'http://ftp.debian.org/debian/pool/main/i/iproute2/iproute2_4.20.0-2_amd64.deb' --output /tmp/iproute2_4.20.0-2_amd64.deb && dpkg -i /tmp/iproute2_4.20.0-2_amd64.deb)
