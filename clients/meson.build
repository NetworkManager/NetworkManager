# SPDX-License-Identifier: LGPL-2.1-or-later

executable(
  'nm-online',
  'nm-online' + '.c',
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
    libnm_libnm_aux_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="nm-online"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
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
