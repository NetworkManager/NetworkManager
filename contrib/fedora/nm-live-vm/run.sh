#!/bin/sh

# Three network interfaces
NET_OPTIONS="-net nic -net user -net nic -net user -net nic -net user"

OS="Linux"
if [ -f /etc/redhat-release ]; then
    OS=`cat /etc/redhat-release | cut -d" " -f1,2,3,4`
fi

if [ "$OS" == "Red Hat Enterprise Linux" ]; then
    # qemu-kvm is installed in /usr/libexec on RHEL6
    # and redirects its output to VNC server

    rpm -q qemu-kvm tigervnc >&2 || exit 1

    PATH=$PATH:/usr/libexec

    qemu-kvm -vnc :0 -m 2048 $NET_OPTIONS -kernel vmlinuz -append video='1024x768' -initrd initramfs.img &

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

    $QEMU -m 2048 -net nic $NET_OPTIONS -kernel vmlinuz -append video='1024x768' -initrd initramfs.img

fi
