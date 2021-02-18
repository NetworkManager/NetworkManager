# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_base = static_library(
  'nm-base',
  include_directories: [
    shared_inc,
    src_inc,
    top_inc,
  ],
  sources: files(
    'nm-ethtool-base.c',
  ),
  dependencies: libnm_glib_aux_dep_link,
)

libnm_base_dep = declare_dependency(
  include_directories: shared_inc,
  dependencies: libnm_glib_aux_dep,
)

libnm_base_dep_link = declare_dependency(
  dependencies: libnm_glib_aux_dep_link,
  link_with: libnm_base,
)
