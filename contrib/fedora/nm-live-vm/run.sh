#!/bin/sh

# Three network interfaces
NET_OPTIONS="-net nic -net user,hostfwd=tcp:127.0.0.1:10022-:22 -net nic -net user -net nic -net user"

OS="Linux"
if [ -f /etc/redhat-release ]; then
    OS=`cat /etc/redhat-release | cut -d" " -f1,2,3,4`
fi

DIR="$(dirname "$(readlink -f "$0")")"
SDIR="$DIR/share"
MEMORY=$((3*1024))

mkdir "$SDIR"

cd "$DIR"

if [ "$OS" == "Red Hat Enterprise Linux" ]; then
    # qemu-kvm is installed in /usr/libexec on RHEL6
    # and redirects its output to VNC server

    rpm -q qemu-kvm tigervnc >&2 || exit 1

    PATH=$PATH:/usr/libexec

    qemu-kvm -vnc :0 -m $MEMORY $NET_OPTIONS -kernel vmlinuz -append "video=1024x768 rootfstype=ramfs" -initrd initramfs.img &

    sleep 1
    vncviewer localhost

else
    # all other distros

    QEMU="qemu-kvm"
    which $QEMU &>2 || {
        ARCH=`uname -m`
        which qemu-system-$ARCH &>2 || { echo "Neither '$QEMU' nor 'qemu-system-$ARCH' available"; exit 1; }
        QEMU="qemu-system-$ARCH -enable-kvm"
    }

    $QEMU -m $MEMORY -net nic $NET_OPTIONS -drive "file=fat:rw:$SDIR,cache=none" -kernel vmlinuz -append "video=1024x768 rootfstype=ramfs" -initrd initramfs.img
fi
