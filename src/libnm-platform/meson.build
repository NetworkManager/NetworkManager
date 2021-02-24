# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_platform = static_library(
  'nm-platform',
  sources: [
    'nm-netlink.c',
    'nm-platform-utils.c',
    'nmp-netns.c',
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
