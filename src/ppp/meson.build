name = 'nm-pppd-plugin'

deps = [
  dl_dep,
  nm_core_dep,
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
  install_dir: pppd_plugin_dir,
)

name = 'nm-ppp-plugin'

deps = [
  nm_dep,
]

linker_script = join_paths(meson.current_source_dir(), 'nm-ppp-plugin.ver')

core_plugins += shared_module(
  name,
  sources: 'nm-ppp-manager.c',
  dependencies: deps,
  link_args: [
    '-Wl,--version-script,@0@'.format(linker_script),
  ],
  link_depends: linker_script,
  install: true,
  install_dir: nm_plugindir,
)
