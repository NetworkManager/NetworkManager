# SPDX-License-Identifier: LGPL-2.1-or-later

nm_pppd_plugin = shared_module(
  'nm-pppd-plugin',
  name_prefix: '',
  sources: 'nm-pppd-plugin.c',
  dependencies: libnm_core_nm_default_dep,
  c_args: [
    '-DG_LOG_DOMAIN="nm-pppd-plugin"',
  ],
  install: true,
  install_dir: pppd_plugin_dir,
)

linker_script = join_paths(meson.current_source_dir(), 'nm-ppp-plugin.ver')

core_plugins += shared_module(
  'nm-ppp-plugin',
  sources: [
    'nm-ppp-manager.c',
  ],
  dependencies: core_plugin_dep,
  c_args: daemon_c_flags,
  link_args: '-Wl,--version-script,@0@'.format(linker_script),
  link_depends: linker_script,
  install: true,
  install_dir: nm_plugindir,
)
