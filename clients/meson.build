# SPDX-License-Identifier: LGPL-2.1+

clients_c_flags = ['-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT']

name = 'nm-online'

executable(
  name,
  name + '.c',
  dependencies: [
    libnm_dep,
    libnm_nm_default_dep,
    libnm_libnm_aux_dep,
  ],
  c_args: clients_c_flags + ['-DG_LOG_DOMAIN="@0@"'.format(name)],
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
