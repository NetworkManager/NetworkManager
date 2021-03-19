# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_base = static_library(
  'nm-base',
  sources: files(
    'nm-ethtool-base.c',
    'nm-net-aux.c',
  ),
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: glib_dep,
)
