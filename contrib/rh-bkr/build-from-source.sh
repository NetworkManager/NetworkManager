#!/bin/bash

set -exv

BUILD_DIR="${BUILD_DIR:-/tmp/nm-build}"
BUILD_ID="${BUILD_ID:-master}"
BUILD_REPO="${BUILD_REPO-https://github.com/NetworkManager/NetworkManager.git}"
BUILD_REPO2="${BUILD_REPO2-git://github.com/NetworkManager/NetworkManager.git}"
BUILD_SNAPSHOT="${BUILD_SNAPSHOT:-}"
ARCH="${ARCH:-`arch`}"
WITH_DEBUG="$WITH_DEBUG"
WITH_SANITIZER="$WITH_SANITIZER"
DO_TEST_BUILD="${DO_TEST_BUILD:-yes}"
DO_TEST_PACKAGE="${DO_TEST_PACKAGE:-yes}"
DO_INSTALL="${DO_INSTALL:-yes}"

if [ -z "$SUDO" ]; then
    unset SUDO
fi

YUM_ARGS=()

if grep -q --quiet Ootpa /etc/redhat-release; then
    YUM_ARGS+=("--enablerepo=rhel-8-buildroot")
fi

$SUDO yum install \
    'perl(XML::Parser)' \
    'perl(YAML)' \
    /usr/bin/dbus-launch \
    ModemManager-glib-devel \
    audit-libs-devel \
    automake \
    bluez-libs-devel \
    dbus-devel \
    dbus-glib-devel \
    dbus-python \
    dhclient \
    gettext-devel \
    git \
    glib2-devel \
    gnutls-devel \
    gobject-introspection-devel \
    gtk-doc \
    intltool \
    iptables \
    jansson-devel \
    libasan \
    libcurl-devel \
    libgudev1-devel \
    libndp-devel \
    libnl3-devel \
    libpsl-devel \
    libselinux-devel \
    libsoup-devel \
    libubsan \
    libudev-devel \
    libuuid-devel \
    mobile-broadband-provider-info-devel \
    newt-devel \
    nss-devel \
    pkgconfig \
    polkit-devel \
    ppp-devel \
    pygobject3-base \
    python3 \
    readline-devel \
    rpm-build \
    strace \
    systemd \
    teamd-devel \
    vala-tools \
    valgrind \
    wireless-tools-devel \
    "${YUM_ARGS[@]}" \
    --skip-broken \
    -y

# for the tests, let's pre-load some modules:
$SUDO modprobe ip_gre

if grep -q Maipo /etc/redhat-release; then
    PYTHON=$(which python2)
else
    # in particular on rhel-8, the pygobject module does not exist for
    # python2. Hence, we prefer python3 over python2.
    PYTHON=$(which python3) || \
    PYTHON=$(which python2) || \
    PYTHON=$(which python)
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

rm -rf "./NetworkManager"

if ! timeout 10m git clone "$BUILD_REPO"; then
    git clone "$BUILD_REPO2"
fi

cd "./NetworkManager/"

# enable randomization for unit-tests.
export NMTST_SEED_RAND=

# if we fetch from a github repository, we also care about the refs to the pull-requests
# fetch them too.
git config --add remote.origin.fetch '+refs/heads/*:refs/heads/*'
git config --add remote.origin.fetch '+refs/tags/*:refs/nmbuild-origin/tags/*'
git config --add remote.origin.fetch '+refs/pull/*:refs/nmbuild-origin/pull/*'
git checkout HEAD^{}
git fetch origin --prune
git checkout -B nmbuild "$BUILD_ID"

echo "HEAD is $(git rev-parse HEAD)"

if [[ "$DO_TEST_BUILD" == yes ]]; then
    NOCONFIGURE=yes ./autogen.sh

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
fi

if [[ "$DO_TEST_PACKAGE" == yes || "$DO_INSTALL" == yes ]]; then
    A=()
    if [[ "$WITH_DEBUG" == yes ]]; then
        A=("${A[@]}" --with debug)
    else
        A=("${A[@]}" --without debug)
    fi
    if [[ "$WITH_SANITIZER" == yes ]]; then
        A=("${A[@]}" --with sanitizer)
    else
        A=("${A[@]}" --without sanitizer)
    fi
    NM_BUILD_SNAPSHOT="${BUILD_SNAPSHOT}" \
    PYTHON="${PYTHON}" \
        ./contrib/fedora/rpm/build_clean.sh -c "${A[@]}"
fi

if [[ "$DO_INSTALL" == yes ]]; then
    pushd "./contrib/fedora/rpm/latest/RPMS/"
        for p in $(ls -1 ./{$ARCH,noarch}/*.rpm | sed -n 's#^\./[^/]\+/\(NetworkManager.*\)-1\.[0-9]\+\..*#\1#p'); do
            $SUDO rpm -e --nodeps $p || true
        done
        $SUDO yum install -y ./{$ARCH,noarch}/*.rpm
    popd

    # ensure that the expected NM is installed.
    COMMIT_ID="$(git rev-parse --verify HEAD | sed 's/^\(.\{10\}\).*/\1/')"
    $SUDO yum list installed NetworkManager | grep -q -e "\.$COMMIT_ID\."

    $SUDO systemctl restart NetworkManager
fi

echo "BUILDING $BUILD_ID COMPLETED SUCCESSFULLY"
