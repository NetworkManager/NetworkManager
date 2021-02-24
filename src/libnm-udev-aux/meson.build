# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_udev_aux = static_library(
  'nm-udev-aux',
  sources: 'nm-udev-utils.c',
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
    libudev_dep,
  ],
)

libnm_udev_aux_dep = declare_dependency(
  link_with: libnm_udev_aux,
)
