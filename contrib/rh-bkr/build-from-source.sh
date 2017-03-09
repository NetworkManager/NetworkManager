#!/bin/bash

set -e
set -xv

BUILD_DIR="${BUILD_DIR:-/tmp/nm-build}"
BUILD_ID="${BUILD_ID:-master}"
BUILD_REPO="${BUILD_REPO-https://github.com/NetworkManager/NetworkManager.git}"
BUILD_REPO2="${BUILD_REPO2-git://github.com/NetworkManager/NetworkManager.git}"
ARCH="${ARCH:-`arch`}"
WITH_DEBUG="$WITH_DEBUG"
DO_TEST_BUILD="${DO_TEST_BUILD:-yes}"
DO_TEST_PACKAGE="${DO_TEST_PACKAGE:-yes}"
DO_INSTALL="${DO_INSTALL:-yes}"

if [ -z "$SUDO" ]; then
    unset SUDO
fi

$SUDO yum install \
    git \
    rpm-build \
    valgrind \
    dbus-devel \
    dbus-glib-devel \
    wireless-tools-devel \
    glib2-devel \
    gobject-introspection-devel \
    gettext-devel \
    pkgconfig \
    libnl3-devel \
    'perl(XML::Parser)' \
    'perl(YAML)' \
    automake \
    ppp-devel \
    nss-devel \
    dhclient \
    readline-devel \
    audit-libs-devel \
    gtk-doc \
    libudev-devel \
    libuuid-devel \
    libgudev1-devel \
    vala-tools \
    iptables \
    bluez-libs-devel \
    systemd \
    libsoup-devel \
    libndp-devel \
    ModemManager-glib-devel \
    newt-devel \
    /usr/bin/dbus-launch \
    pygobject3-base \
    dbus-python \
    libselinux-devel \
    polkit-devel \
    teamd-devel \
    jansson-devel \
    -y

# for the tests, let's pre-load some modules:
$SUDO modprobe ip_gre

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

rm -rf "./NetworkManager"

if ! timeout 10m git clone "$BUILD_REPO"; then
    git clone "$BUILD_REPO2"
fi

cd "./NetworkManager/"
git checkout "$BUILD_ID"
echo "HEAD is $(git rev-parse HEAD)"

if [[ "$DO_TEST_BUILD" == yes ]]; then
    NOCONFIGURE=yes ./autogen.sh

    ./configure \
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
        --with-netconfig=yes \
        --with-crypto=nss \
        --with-session-tracking=systemd \
        --with-consolekit=yes \
        --with-systemd-logind=yes \
        --with-consolekit=yes

    make -j20
    make check -k
fi

if [[ "$DO_TEST_PACKAGE" == yes || "$DO_INSTALL" == yes ]]; then
    A=()
    if [[ "$WITH_DEBUG" == yes ]]; then
        A=("${A[@]}" --with debug)
    fi
    ./contrib/fedora/rpm/build_clean.sh -c "${A[@]}"
fi

if [[ "$DO_INSTALL" == yes ]]; then
    pushd "./contrib/fedora/rpm/latest/RPMS/$ARCH/"
        for p in $(ls -1 ./*.rpm | sed 's#.*\(NetworkManager.*\)-1\.[0-9]\..*#\1#'); do
            $SUDO rpm -e --nodeps $p || true
        done
        $SUDO yum install -y ./*.rpm
    popd

    # ensure that the expected NM is installed.
    COMMIT_ID="$(git rev-parse --verify HEAD | sed 's/^\(.\{10\}\).*/\1/')"
    $SUDO yum list installed NetworkManager | grep -q -e "\.$COMMIT_ID\."

    $SUDO systemctl restart NetworkManager
fi

echo "BUILDING $BUILD_ID COMPLETED SUCCESSFULLY"
