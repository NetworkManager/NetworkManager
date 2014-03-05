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
git clean -fdx
export CFLAGS='-g -Og'
export CXXFLAGS='-g -Og'
./autogen.sh --prefix=/usr \
             --exec-prefix=/usr \
             --libdir=/usr/lib \
             --sysconfdir=/etc \
             --localstatedir=/var \
             --with-nmtui=yes \
             --enable-gtk-doc || exit 1
make || exit 1
#make check || exit 1
make install || exit 1
cat <<EOF > /etc/NetworkManager/NetworkManager.conf
[main]
plugins=ifcfg-rh
[logging]
level=DEBUG
domains=ALL
EOF
/bin/systemctl enable NetworkManager.service || exit 1
/bin/systemctl enable sshd.service || exit 1

sed -e 's/^#\?\(PermitRootLogin *\).*/\1yes/' \
    -e 's/^#\?\(PermitEmptyPasswords *\).*/\1yes/' \
    -i /etc/ssh/sshd_config

mkdir /mnt/sda1
echo "/dev/sda1 /mnt/sda1 vfat defaults 1 2" >> /etc/fstab

git gc
