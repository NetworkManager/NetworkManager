# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_platform = static_library(
  'nm-platform',
  include_directories: [
    src_inc,
  ],
  sources: [
    'nm-netlink.c',
    'nm-platform-utils.c',
    'nmp-netns.c',
  ],
  dependencies: [
    glib_nm_default_dep,
  ],
)

libnm_platform_dep = declare_dependency(
  include_directories: [
    src_inc,
  ],
  dependencies: [
    libnm_glib_aux_dep_link,
  ],
  link_with: libnm_platform,
)
