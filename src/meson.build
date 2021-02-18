# SPDX-License-Identifier: LGPL-2.1-or-later

src_inc = include_directories('.')

subdir('libnm-glib-aux')
subdir('libnm-log-null')
subdir('libnm-log-core')
subdir('libnm-systemd-shared')
subdir('libnm-udev-aux')
subdir('libnm-base')
subdir('libnm-platform')
subdir('libnm-core-public')
subdir('libnm-core-intern')
subdir('libnm-core-aux-intern')
subdir('libnm-core-impl')
subdir('libnm-core-aux-extern')
subdir('core')

if enable_tests
  subdir('libnm-glib-aux/tests')
  subdir('libnm-platform/tests')
  subdir('libnm-core-impl/tests')
endif
