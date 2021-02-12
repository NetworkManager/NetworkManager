# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_core_aux_extern = static_library(
  'nm-core-aux-extern',
  sources: files(
    'nm-libnm-core-aux.c',
  ),
  dependencies: [
    libnm_core_aux_intern_dep,
    libnm_core_public_dep,
    libnm_glib_aux_dep,
    glib_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="libnm"',
  ],
)

libnm_core_aux_extern_dep = declare_dependency(
  include_directories: [
    src_inc,
  ],
  dependencies: [
    libnm_core_aux_intern_dep,
    libnm_core_public_dep,
    libnm_glib_aux_dep,
    glib_dep,
  ],
)

libnm_core_aux_extern_dep_link = declare_dependency(
  dependencies: libnm_core_aux_extern_dep,
  link_with: libnm_core_aux_extern,
)
