# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_log_core = static_library(
  'nm-log-core',
  sources: 'nm-logging.c',
  include_directories: [
    shared_inc,
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_nm_default_dep,
    libsystemd_dep,
  ],
)

libnm_log_core_dep = declare_dependency(
  include_directories: shared_inc,
  dependencies: [
    libnm_glib_aux_dep_link,
  ],
  link_with: libnm_log_core,
)
