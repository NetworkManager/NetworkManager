# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_client_aux_extern = static_library(
  'nm-client-aux-extern',
  sources: files(
    'nm-libnm-aux.c',
  ),
  dependencies: [
    libnm_core_public_dep,
    libnm_dep,
  ],
)

libnm_client_aux_extern_dep = declare_dependency(
  link_with: [libnm_client_aux_extern],
)
