# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_base = static_library(
  'nm-base',
  include_directories: [
    src_inc,
    top_inc,
  ],
  sources: files(
    'nm-ethtool-base.c',
  ),
  dependencies: glib_dep,
)

libnm_base_dep = declare_dependency(
  dependencies: glib_dep,
)

libnm_base_dep_link = declare_dependency(
  dependencies: glib_dep,
  link_with: [
    libnm_base,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)
