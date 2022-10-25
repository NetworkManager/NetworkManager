# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_lldp = static_library(
  'nm-lldp',
  sources: [
    'nm-lldp-neighbor.c',
    'nm-lldp-network.c',
    'nm-lldp-rx.c',
  ],
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
    libudev_dep,
  ],
)
