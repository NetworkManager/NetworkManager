# SPDX-License-Identifier: LGPL-2.1-or-later

executable(
  'nm-online',
  'nm-online' + '.c',
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
  link_with: [
    libnm_client_aux_extern,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
)

subdir('common')
subdir('cli')

if enable_nmtui
  subdir('tui')
endif

if enable_nm_cloud_setup
  subdir('cloud-setup')
endif
