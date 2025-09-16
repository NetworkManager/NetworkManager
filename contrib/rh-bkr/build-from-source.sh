#!/bin/bash

set -exv

#
# supported environment variables to tweak the build
#
BUILD_DIR="${BUILD_DIR:-$HOME/nm-build}"
BUILD_ID="${BUILD_ID:-main}"
BUILD_REPO="${BUILD_REPO}"
BUILD_SNAPSHOT="${BUILD_SNAPSHOT:-}"
ARCH="${ARCH:-$(arch)}"
WITH_DEBUG="$WITH_DEBUG"
WITH_SANITIZER="$WITH_SANITIZER"
DO_TEST_BUILD="${DO_TEST_BUILD:-yes}"
DO_TEST_PACKAGE="${DO_TEST_PACKAGE:-yes}"
DO_INSTALL="${DO_INSTALL:-yes}"
SUDO="$SUDO"
INSTALL_DEPENDENCIES="${INSTALL_DEPENDENCIES:-yes}"

if [ -z "$SUDO" ]; then
    unset SUDO
fi

YUM_ARGS=()
if grep -q --quiet Ootpa /etc/redhat-release; then
    YUM_ARGS+=("--enablerepo=rhel-8-buildroot")
fi
if grep -q --quiet Coughlan /etc/redhat-release; then
    # We have different key for CentOS
    if grep -q --quiet CentOS /etc/redhat-release; then
        rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial*
    # And for RHEL10
    else
        rpmkeys --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
        YUM_ARGS+=('--repofrompath=buildroot,http://download.devel.redhat.com/rhel-$releasever/nightly/BUILDROOT-$releasever/latest-BUILDROOT-$releasever-RHEL-$releasever/compose/Buildroot/$basearch/os')
    fi
    YUM_ARGS+=('--nogpg')
fi

if [[ "$INSTALL_DEPENDENCIES" == yes ]]; then
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
      firewalld-filesystem \
      gettext-devel \
      git \
      glib2-devel \
      gnutls-devel \
      gobject-introspection-devel \
      gtk-doc \
      intltool \
      iproute-tc \
      iptables \
      jansson-devel \
      libasan \
      libcurl-devel \
      libgudev1-devel \
      libndp-devel \
      libnl3-devel \
      libnvme-devel \
      libpsl-devel \
      libselinux-devel \
      libsoup-devel \
      libubsan \
      libudev-devel \
      libuuid-devel \
      make \
      meson \
      mobile-broadband-provider-info-devel \
      newt-devel \
      nss-devel \
      pkgconfig \
      polkit-devel \
      ppp-devel \
      pygobject3-base \
      python3-gobject-devel \
      python3 \
      python3-pexpect \
      readline-devel \
      rpm-build \
      strace \
      systemd \
      teamd-devel \
      vala-tools \
      vala \
      valgrind \
      wireless-tools-devel \
      "${YUM_ARGS[@]}" \
      --skip-broken \
      -y
fi

# libnvme >= 1.5 is available in RHEL 9.4+, disable when missing
if pkgconf 'libnvme >= 1.5'; then
    _WITH_NBFT="true"
else
    _WITH_NBFT="false"
fi

if [[ "$DO_TEST_BUILD" == yes ]]; then
    # for the tests, let's pre-load some modules:
    $SUDO modprobe ip_gre || true
fi

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

BUILD_REPO_GITLAB="https://gitlab.freedesktop.org/NetworkManager/NetworkManager.git"
BUILD_REPO_GITHUB="https://github.com/NetworkManager/NetworkManager.git"
if [ -z "$BUILD_REPO" ]; then
    BUILD_REPO="$BUILD_REPO_GITLAB"
fi

rm -rf "./NetworkManager"
mkdir "./NetworkManager/"
cd "./NetworkManager/"
git init .
git config user.email nm-build-script@example.com
git config user.name "Build Script Bot"

_git_setup_remote() {
    local REMOTE="$1"
    local MY_BUILD_REPO="$2"

    git remote add "$REMOTE" "$MY_BUILD_REPO"

    git config remote."$REMOTE".tagOpt --no-tags
    git config --unset-all remote."$REMOTE".fetch
    git config --add remote."$REMOTE".fetch "+refs/heads/*:refs/remotes/$REMOTE/*"
    git config --add remote."$REMOTE".fetch "+refs/heads/*:refs/nmbuild-$REMOTE/heads/*"
    git config --add remote."$REMOTE".fetch "+refs/tags/*:refs/nmbuild-$REMOTE/tags/*"

    if [ "$REMOTE" == origin ]; then
        git config --add remote."$REMOTE".fetch '+refs/heads/*:refs/heads/*'
        git config --add remote."$REMOTE".fetch "+refs/tags/*:refs/tags/*"
    fi
    if [ "$MY_BUILD_REPO" == "$BUILD_REPO_GITHUB" ]; then
        git config --add remote."$REMOTE".fetch "+refs/pull/*/head:refs/remotes/$REMOTE/pr/*"
    fi
    if [ "$MY_BUILD_REPO" == "$BUILD_REPO_GITLAB" ]; then
        git config --add remote."$REMOTE".fetch "+refs/merge-requests/*/head:refs/remotes/$REMOTE/pr/*"
    fi
}

_git_setup_remote origin "$BUILD_REPO"
_git_setup_remote github "$BUILD_REPO_GITHUB"
if [ "$BUILD_REPO" != "$BUILD_REPO_GITLAB" ]; then
    _git_setup_remote gitlab "$BUILD_REPO_GITLAB"
fi

git -c user.email=bogus@nowhere.com -c user.name="Nobody Unperson" commit --allow-empty -m dummy-commit
git checkout HEAD^{}

git fetch github
git fetch --all --prune

git show-ref

git checkout -B nmbuild "$BUILD_ID"

echo "HEAD is $(git rev-parse HEAD)"

# enable randomization for unit-tests.
export NMTST_SEED_RAND=
LAST_TAG=$(git describe | cut -d "." -f 2)

if [ "$LAST_TAG" -lt "47" ]; then
    export USE_AUTOTOOLS=1
fi

if [[ "$DO_TEST_BUILD" == yes ]]; then

    if [[ $USE_AUTOTOOLS != 1 ]]; then
        meson setup "./build" \
            -Dwarning_level=2 \
            --prefix=/opt/test \
            --sysconfdir=/etc \
            -Ddocs=true \
            -Dmore_asserts=all \
            -Dmore_logging=true \
            -Dintrospection=true \
            -Dvalgrind=true \
            -Dconcheck=true \
            -Difcfg_rh=true \
            -Difupdown=true \
            -Dvapi=true \
            -Dpolkit=true \
            -Dnmtui=true \
            -Dmodem_manager=true \
            -Dsuspend_resume=systemd \
            -Dtests=root \
            -Dnetconfig=no \
            -Dresolvconf=no \
            -Dcrypto=nss \
            -Dsession_tracking=systemd \
            -Dsession_tracking_consolekit=true \
            -Dconfig_logging_backend_default=syslog \
            -Dconfig_wifi_backend_default=wpa_supplicant \
            -Dlibaudit=yes-disabled-by-default \
            -Dnm_cloud_setup=true \
            -Dconfig_dhcp_default=internal \
            -Dconfig_dns_rc_manager_default=auto \
            -Diptables=/usr/sbin/iptables \
            -Dnft=/usr/bin/nft \
            -Dnbft=${_WITH_NBFT}

	ninja -C ./build
	ninja test -C ./build
    else
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
            --enable-compile-warnings=yes \
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
            --enable-tests=root \
            --with-netconfig=/path/does/not/exist/netconfig \
            --with-resolvconf=/path/does/not/exist/resolvconf \
            --with-crypto=nss \
            --with-session-tracking=systemd \
            --with-consolekit=yes \
            --with-systemd-logind=yes \
            --with-consolekit=yes

	# We see some OOM when we have 8 cores and 12GB RAM, lowering to 16 from 20.
        proc=$(nproc); make -j$((proc*2))
        make check -k
    fi
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
        ./contrib/fedora/rpm/build_clean.sh -c --with test "${A[@]}"
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
