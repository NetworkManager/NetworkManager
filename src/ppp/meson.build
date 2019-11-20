name = 'nm-pppd-plugin'

c_flags = [
  '-DG_LOG_DOMAIN="@0@"'.format(name),
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_GLIB',
]

nm_pppd_plugin = shared_module(
  name,
  name_prefix: '',
  sources: name + '.c',
  dependencies: libnm_core_nm_default_dep,
  c_args: c_flags,
  install: true,
  install_dir: pppd_plugin_dir,
)

name = 'nm-ppp-plugin'

linker_script = join_paths(meson.current_source_dir(), 'nm-ppp-plugin.ver')

core_plugins += shared_module(
  name,
  sources: 'nm-ppp-manager.c',
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
  link_args: '-Wl,--version-script,@0@'.format(linker_script),
  link_depends: linker_script,
  install: true,
  install_dir: nm_plugindir,
)
