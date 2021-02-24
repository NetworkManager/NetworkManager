# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_client_test = static_library(
  'nm-client-test',
  sources: files(
    'nm-test-utils-impl.c',
  ),
  include_directories: [
    libnm_core_public_inc,
    libnm_client_public_inc,
    src_inc,
    top_inc,
  ],
  dependencies: [
    libnm_core_public_dep,
    glib_dep,
  ],
)
