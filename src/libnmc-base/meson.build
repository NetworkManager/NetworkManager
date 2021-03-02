# SPDX-License-Identifier: LGPL-2.1-or-later

libnmc_base = static_library(
  'nmc-base',
  sources: files(
    'nm-client-utils.c',
    'nm-secret-agent-simple.c',
    'nm-vpn-helpers.c',
    'nm-polkit-listener.c',
  ),
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
)
