# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_core_aux_intern = static_library(
  'nm-core-aux-intern',
  sources: files(
    'nm-auth-subject.c',
    'nm-libnm-core-utils.c',
  ),
  dependencies: [
    libnm_core_public_dep,
    libnm_glib_aux_dep,
    glib_dep,
  ],
)

libnm_core_aux_intern_dep = declare_dependency(
  include_directories: [
    shared_inc,
    src_inc,
    top_inc,
  ],
  dependencies: [
    libnm_core_public_dep,
    glib_dep,
  ],
)

libnm_core_aux_intern_dep_link = declare_dependency(
  dependencies: libnm_core_aux_intern_dep,
  link_with: libnm_core_aux_intern,
)
