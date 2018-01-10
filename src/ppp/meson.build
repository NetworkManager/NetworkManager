name = 'nm-pppd-plugin'

deps = [
  dl_dep,
  nm_core_dep
]

nm_pppd_plugin = shared_module(
  name,
  name_prefix: '',
  sources: name + '.c',
  include_directories: src_inc,
  dependencies: deps,
  c_args: [
    '-DG_LOG_DOMAIN="@0@"'.format(name),
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_GLIB',
  ],
  install: true,
  install_dir: pppd_plugin_dir
)

name = 'nm-ppp-plugin'

deps = [
  libnmdbus_dep,
  nm_dep
]

symbol_map = join_paths(meson.current_source_dir(), 'nm-ppp-plugin.ver')

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(symbol_map)
endif

core_plugins += shared_module(
  name,
  sources: 'nm-ppp-manager.c',
  dependencies: deps,
  c_args: '-DPPPD_PLUGIN_DIR="@0@"'.format(pppd_plugin_dir),
  link_args: ldflags,
  link_depends: symbol_map,
  install: true,
  install_dir: nm_pkglibdir
)
