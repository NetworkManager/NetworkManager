#!/bin/bash

date '+%Y%m%d-%H%M%S'; uname -a
date '+%Y%m%d-%H%M%S'; locale -a
date '+%Y%m%d-%H%M%S'; env
date '+%Y%m%d-%H%M%S'; meson --version
date '+%Y%m%d-%H%M%S'; ! which dpkg || dpkg -l
date '+%Y%m%d-%H%M%S'; ! which yum  || yum list installed
date '+%Y%m%d-%H%M%S'; git clean -fdx ; BUILD_TYPE=autotools CC=gcc   WITH_DOCS=1 WITH_VALGRIND=1 contrib/scripts/nm-ci-run.sh
date '+%Y%m%d-%H%M%S'; rm -rf /tmp/nm-docs-html; mv build/INST/share/gtk-doc/html /tmp/nm-docs-html
date '+%Y%m%d-%H%M%S'; git clean -fdx ; BUILD_TYPE=meson     CC=gcc   WITH_DOCS=1 WITH_VALGRIND=1 contrib/scripts/nm-ci-run.sh
date '+%Y%m%d-%H%M%S'; git clean -fdx ; BUILD_TYPE=autotools CC=clang WITH_DOCS=0 contrib/scripts/nm-ci-run.sh
date '+%Y%m%d-%H%M%S'; git clean -fdx ; BUILD_TYPE=meson     CC=clang WITH_DOCS=0 contrib/scripts/nm-ci-run.sh
date '+%Y%m%d-%H%M%S'; git clean -fdx ; ! grep -q '^NAME=.*\(Fedora\|CentOS\)' /etc/os-release || ./contrib/fedora/rpm/build_clean.sh -g -w crypto_gnutls -w debug -w iwd -w test -W meson
date '+%Y%m%d-%H%M%S'; git clean -fdx ; ! grep -q '^NAME=.*\(Fedora\)'         /etc/os-release || ./contrib/fedora/rpm/build_clean.sh -g -w crypto_gnutls -w debug -w iwd -w test -w meson
date '+%Y%m%d-%H%M%S'; git clean -fdx ; test "$NM_BUILD_TARBALL" != 1 || ( SIGN_SOURCE=0 ./contrib/fedora/rpm/build_clean.sh -r && mv ./NetworkManager-1*.tar.xz /tmp/ && mv ./contrib/fedora/rpm/latest/SRPMS/NetworkManager-1*.src.rpm /tmp/ )
date '+%Y%m%d-%H%M%S'; git clean -fdx
date '+%Y%m%d-%H%M%S'; mv /tmp/nm-docs-html ./docs-html
date '+%Y%m%d-%H%M%S'; test "$NM_BUILD_TARBALL" != 1 || mv /tmp/NetworkManager-1*.tar.xz /tmp/NetworkManager-1*.src.rpm ./
