# SPDX-License-Identifier: LGPL-2.1-or-later

nm_pppd_plugin = shared_module(
  'nm-pppd-plugin',
  name_prefix: '',
  sources: [
    'nm-pppd-compat.c',
    'nm-pppd-plugin.c',
  ],
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    libnm_core_public_dep,
    glib_dep,
    pppd_dep,
  ],
  link_with: [
    libnm_core_impl,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
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
  link_args: '-Wl,--version-script,@0@'.format(linker_script),
  link_depends: linker_script,
  install: true,
  install_dir: nm_plugindir,
)
