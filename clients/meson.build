name = 'nm-online'

deps = [
  libnm_dep,
  nm_core_dep
]

clients_cflags = [
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  '-DNMLOCALEDIR="@0@"'.format(nm_localedir),
]

cflags = clients_cflags + [
  '-DG_LOG_DOMAIN="@0@"'.format(name),
]

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(linker_script_binary)
endif

executable(
  name,
  name + '.c',
  dependencies: deps,
  c_args: cflags,
  link_args: ldflags,
  link_depends: linker_script_binary,
  install: true
)

subdir('common')

if enable_nmcli
  subdir('cli')
endif

if enable_nmtui
  subdir('tui')
endif
