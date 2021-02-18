# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_udev_aux = static_library(
  'nm-udev-aux',
  sources: 'nm-udev-utils.c',
  dependencies: [
    glib_nm_default_dep,
    libudev_dep,
  ],
)

libnm_udev_aux_dep = declare_dependency(
  include_directories: shared_inc,
  link_with: libnm_udev_aux,
)
