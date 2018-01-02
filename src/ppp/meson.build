name = 'nm-pppd-plugin'

deps = [
  dl_dep,
  glib_dep
]

nm_pppd_plugin = shared_module(
  name,
  name_prefix: '',
  sources: [name + '.c', libnm_core_enum[1]],
  include_directories: core_incs,
  dependencies: deps,
  c_args: [
    '-DG_LOG_DOMAIN="nm-pppd-plugin"',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_GLIB',
  ],
  install: true,
  install_dir: pppd_plugin_dir
)

name = 'nm-ppp-plugin'

deps = [
  core_dep,
  libnmdbus_dep
]

cflags = [
  '-DPPPD_PLUGIN_DIR="@0@"'.format(pppd_plugin_dir),
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DAEMON',
]

symbol_map = join_paths(meson.current_source_dir(), name + '.ver')

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(symbol_map)
endif

core_plugins += shared_module(
  name,
  sources: 'nm-ppp-manager.c',
  dependencies: deps,
  c_args: cflags,
  link_args: ldflags,
  link_depends: symbol_map,
  install: true,
  install_dir: nm_pkglibdir
)
