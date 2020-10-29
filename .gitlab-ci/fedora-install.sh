#!/bin/bash

date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<7\>' /etc/os-release ) || yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<7\>' /etc/os-release ) || yum install -y glibc-common
date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<7\>' /etc/os-release ) || localedef -c -i pl_PL -f UTF-8 pl_PL.UTF-8 && locale -a
date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<7\>' /etc/os-release ) || yum install -y python36-dbus python36-gobject-base

date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<8\>' /etc/os-release ) || dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<8\>' /etc/os-release ) || dnf install -y 'dnf-command(config-manager)'
date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<8\>' /etc/os-release ) || dnf config-manager --set-enabled PowerTools
date '+%Y%m%d-%H%M%S'; ! ( grep -q '^NAME=.*\(CentOS\)' /etc/os-release && grep -q '^VERSION_ID=.*\<8\>' /etc/os-release ) || curl https://copr.fedorainfracloud.org/coprs/nmstate/nm-build-deps/repo/epel-8/nmstate-nm-build-deps-epel-8.repo > /etc/yum.repos.d/nmstate-nm-build-deps-epel-8.repo

date '+%Y%m%d-%H%M%S'; NM_NO_EXTRA=1 NM_INSTALL="yum install -y" ./contrib/fedora/REQUIRED_PACKAGES
date '+%Y%m%d-%H%M%S'; yum install -y glibc-langpack-pl ccache clang which

# containers have "tsflags=nodocs" in /etc/dnf/dnf.conf. We need /usr/shared/gtk-doc/html
# to generate proper documentation.
date '+%Y%m%d-%H%M%S'; yum reinstall -y --setopt='tsflags=' glib2-doc

date '+%Y%m%d-%H%M%S'; ! which dnf || dnf install -y python3-dnf-plugins-core
date '+%Y%m%d-%H%M%S'; ! which dnf || dnf debuginfo-install -y glib2
date '+%Y%m%d-%H%M%S';   which dnf || debuginfo-install -y glib2

date '+%Y%m%d-%H%M%S'; contrib/scripts/nm-ci-patch-gtkdoc.sh || true

date '+%Y%m%d-%H%M%S'; test -x /usr/bin/ninja || ! test -x /usr/bin/ninja-build || ln -s /usr/bin/ninja-build /usr/bin/ninja

