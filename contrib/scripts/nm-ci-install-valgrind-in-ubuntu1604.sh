#!/bin/bash

set -exv

# Ubuntu 16.04 (trusty) ships a valgrind version where __get_cpuid() announces
# rdrand support, but later valgrind crashes with unsupported opcode.
#
# See https://bugs.kde.org/show_bug.cgi?id=353370#c9
#     https://bugs.launchpad.net/ubuntu/+source/valgrind/+bug/1501545
#
# We call rdrand for hash-tables of systemd:
# https://github.com/systemd/systemd/blob/e7b621ee1f1abfbcaae1cd17da4d815daf218679/src/basic/random-util.c#L36
#
# Work around that by installing valgrind from bionic.

grep -q 'PRETTY_NAME="Ubuntu 16.04.6 LTS"' /etc/os-release || exit 0
dpkg -s valgrind | grep -q 'Version: 1:3.11.0-1ubuntu4.2$' || exit 0


cat <<EOF > /etc/apt/sources.list.d/bionic1804.list
deb http://us.archive.ubuntu.com/ubuntu/ bionic main
EOF

cat <<EOF > /etc/apt/preferences.d/bionic1804.pref
Package: *
Pin: release n=bionic
Pin-Priority: -10

Package: valgrind
Pin: release n=bionic
Pin-Priority: 500
EOF

apt-get update

apt-get install valgrind -y
