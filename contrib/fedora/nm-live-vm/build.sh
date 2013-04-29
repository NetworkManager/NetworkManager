#!/bin/bash

NAME="nm-live-vm"
NM_BRANCH="master"
BUILD_PACKAGES="qemu febootstrap mock rpmdevtools"
ARCH=i386
ROOT="fedora-18-$ARCH"
TREE="/var/lib/mock/$ROOT/root"
PACKAGES="kernel passwd git autoconf automake libtool intltool gtk-doc libnl3-devel
    dbus-glib-devel libgudev1-devel libuuid-devel nss-devel ppp-devel dhclient
    bash-completion man-db man-pages vim-minimal gdb"
KERNEL_URL=http://kojipkgs.fedoraproject.org/packages/kernel/3.8.5/201.fc18/i686/kernel-3.8.5-201.fc18.i686.rpm
KERNEL=`basename "${KERNEL_URL%.rpm}"`
#RELEASE="http://kojipkgs.fedoraproject.org/packages/fedora-release/18/1/noarch/fedora-release-18-1.noarch.rpm"
#PACKAGES="systemd bash"

test "$EUID" -eq 0 || { echo "$0 must be run as root"; exit 1; }

do_prepare() {
    echo "Installing build packages..."
    rpm -q $BUILD_PACKAGES || yum install $BUILD_PACKAGES || exit 1
    echo
}

do_chroot() {
    echo "Building the chroot..."
    mock -r "$ROOT" --init || exit 1
    mock -r "$ROOT" --install $PACKAGES || exit 1
    #mock -r "$ROOT" --installdeps NetworkManager || exit 1
    mock -r "$ROOT" --chroot cp /sbin/init /init || exit 1
    echo
}

do_build() {
    echo "Building NetworkManager..."
    cp nm-make-script.sh $TREE/usr/local/sbin/nm-make-script || exit 1
    mock -r "$ROOT" --chroot "/usr/local/sbin/nm-make-script $NM_BRANCH" || exit 1
    test -f "$TREE/usr/sbin/NetworkManager" || ( echo "NetworkManager binary not found"; exit 1; )
    echo
}

do_live_vm() {
    echo "Preparing kernel and initrd..." || exit 1
    mkdir -p $NAME || exit 1
    cp $TREE/boot/vmlinuz* $NAME/vmlinuz || exit 1
    { ( cd "$TREE" && find -print0 | cpio -o0c ) || exit 1; } | gzip > $NAME/initramfs.img || exit 1
    cp run.sh $NAME/run.sh
}

do_archive() {
    echo "Creating the archive..."
    tar -czvf $NAME.tar.gz $NAME || exit 1
    EXTRACT_SCRIPT=$(sed -e "s/__NAME_PLACEHOLDER__/$NAME/g" < self-extract.sh)
    echo "$EXTRACT_SCRIPT" | cat - ${NAME}.tar.gz > ${NAME}-bundle.sh || exit 1
    chmod +x ${NAME}-bundle.sh || exit 1
    echo "Successfully completed"
    echo
    echo "Now you can run and/or distribute: ${NAME}-bundle.sh"
}


if [ "$1" = "-n" ]; then
    test -n "$2" || { echo "Name for initramfs is expected"; exit 1; }
    NAME=$2
    shift 2
fi

if [ "$1" = "-b" ]; then
    test -n "$2" || { echo "NM branch (commit) is expected"; exit 1; }
    NM_BRANCH=$2
    shift 2
fi

if [ $# -eq 0 ]; then
    do_prepare
    do_chroot
    do_build
    do_live_vm
    do_archive
    exit 0
fi

while [ $# -gt 0 ]; do
    do_$1; shift
    exit 0
done

echo "Wrong number of arguments."
exit 1
