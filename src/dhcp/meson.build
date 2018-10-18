name = 'nm-dhcp-helper'

cflags = [
  '-DG_LOG_DOMAIN="@0@"'.format(name),
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_GLIB',
]

executable(
  name,
  name + '.c',
  dependencies: nm_core_dep,
  c_args: cflags,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
