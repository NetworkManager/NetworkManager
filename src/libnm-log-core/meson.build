# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_log_core = static_library(
  'nm-log-core',
  sources: 'nm-logging.c',
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    libsystemd_dep,
    glib_dep,
  ],
)
