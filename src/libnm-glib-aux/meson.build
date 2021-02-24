# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_glib_aux = static_library(
  'nm-glib-aux',
  sources: files(
    'nm-dbus-aux.c',
    'nm-dedup-multi.c',
    'nm-enum-utils.c',
    'nm-errno.c',
    'nm-hash-utils.c',
    'nm-io-utils.c',
    'nm-json-aux.c',
    'nm-keyfile-aux.c',
    'nm-logging-base.c',
    'nm-random-utils.c',
    'nm-ref-string.c',
    'nm-secret-utils.c',
    'nm-shared-utils.c',
    'nm-time-utils.c',
  ),
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: glib_dep,
  link_with: [
    libc_siphash,
    libnm_std_aux,
  ],
)

libnm_glib_aux_dep = declare_dependency(
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
  ],
)

libnm_glib_aux_dep_link = declare_dependency(
  dependencies: libnm_glib_aux_dep,
  link_with: libnm_glib_aux,
)
