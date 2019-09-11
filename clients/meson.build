name = 'nm-online'

deps = [
  libnm_dep,
  libnm_nm_default_dep,
]

clients_c_flags = [
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
]

c_flags = clients_c_flags + [
  '-DG_LOG_DOMAIN="@0@"'.format(name),
]

executable(
  name,
  name + '.c',
  dependencies: deps,
  c_args: c_flags,
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
