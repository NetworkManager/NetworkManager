#!/bin/bash

set -ex

IS_FEDORA=0
IS_CENTOS=0
CENTOS_VERSION=0
grep -q '^NAME=.*\(CentOS\)' /etc/os-release && IS_CENTOS=1
grep -q '^NAME=.*\(Fedora\)' /etc/os-release && IS_FEDORA=1
if [ $IS_CENTOS = 1 ]; then
    if grep -q '^VERSION_ID=.*\<7\>' /etc/os-release ; then
        CENTOS_VERSION=7
    elif grep -q '^VERSION_ID=.*\<8\>' /etc/os-release ; then
        CENTOS_VERSION=8
    elif grep -q '^VERSION_ID=.*\<9\>' /etc/os-release ; then
        CENTOS_VERSION=9
    else
        exit 1
    fi
    if grep -q "^NAME.*Stream" /etc/os-release ; then
        CENTOS_VERSION="stream$CENTOS_VERSION"
    fi
fi

 if [ "$IS_CENTOS" = 1 ]; then
    if [ "$CENTOS_VERSION" = 7 ]; then
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
        yum install -y glibc-common
        localedef -c -i pl_PL -f UTF-8 pl_PL.UTF-8
        locale -a
        yum install -y python36-dbus python36-gobject-base
    elif [ "$CENTOS_VERSION" = 8 -o "$CENTOS_VERSION" = stream8 ]; then
        if [ "$CENTOS_VERSION" = 8 ]; then
            # CentOS Linux 8 is now EOF and plain `dnf upgrade` does not work. We need
            # to patch the mirror list.
            sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
            sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
        fi
        dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
        dnf install -y 'dnf-command(config-manager)'
        dnf config-manager --set-enabled powertools || \
          dnf config-manager --set-enabled PowerTools
        curl https://copr.fedorainfracloud.org/coprs/nmstate/nm-build-deps/repo/epel-8/nmstate-nm-build-deps-epel-8.repo > /etc/yum.repos.d/nmstate-nm-build-deps-epel-8.repo
    elif [ "$CENTOS_VERSION" = stream9 ]; then
        dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm
        dnf install -y 'dnf-command(config-manager)'
        dnf config-manager --set-enabled crb
        curl https://copr.fedorainfracloud.org/coprs/nmstate/nm-build-deps/repo/epel-9/nmstate-nm-build-deps-epel-9.repo > /etc/yum.repos.d/nmstate-nm-build-deps-epel-9.repo
    else
        exit 1
    fi
fi


NM_NO_EXTRA=1 NM_INSTALL="yum install -y" ./contrib/fedora/REQUIRED_PACKAGES
yum install -y glibc-langpack-pl ccache clang

# containers have "tsflags=nodocs" in /etc/dnf/dnf.conf. We need /usr/shared/gtk-doc/html
# to generate proper documentation.
yum reinstall -y --setopt='tsflags=' glib2-doc

if command -v dnf &>/dev/null; then
    dnf install -y python3-dnf-plugins-core
    dnf debuginfo-install -y glib2
else
    debuginfo-install -y glib2
fi

contrib/scripts/nm-ci-patch-gtkdoc.sh || true

if [ -x /usr/bin/ninja ] && ! [ -x /usr/bin/ninja-build ]; then
    ln -s /usr/bin/ninja-build /usr/bin/ninja
fi

if [ $IS_FEDORA = 1 ]; then
    TEMPLATE_SHA="$(sed -n 's/^.templates_sha: *\&template_sha *\([0-9a-f]\+\) .*/\1/p' ./.gitlab-ci/ci.template)"
    test -n "$TEMPLATE_SHA"
    dnf install -y python3-pip
    pip3 install "git+http://gitlab.freedesktop.org/freedesktop/ci-templates@$TEMPLATE_SHA"
fi
