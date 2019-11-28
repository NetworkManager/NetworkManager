clients_c_flags = ['-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT']

name = 'nm-online'

deps = [
  libnm_dep,
  libnm_nm_default_dep,
]

executable(
  name,
  name + '.c',
  dependencies: deps,
  c_args: clients_c_flags + ['-DG_LOG_DOMAIN="@0@"'.format(name)],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
)

subdir('common')

if enable_nmcli
  subdir('cli')
endif

if enable_nmtui
  subdir('tui')
endif

if enable_nm_cloud_setup
  subdir('cloud-setup')
endif
