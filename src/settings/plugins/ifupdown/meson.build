# SPDX-License-Identifier: LGPL-2.1-or-later

libnms_ifupdown_core = static_library(
  'nms-ifupdown-core',
  sources: files(
    'nms-ifupdown-interface-parser.c',
    'nms-ifupdown-parser.c',
  ),
  dependencies: core_default_dep,
  c_args: daemon_c_flags,
)

libnm_settings_plugin_ifupdown = shared_module(
  'nm-settings-plugin-ifupdown',
  sources: 'nms-ifupdown-plugin.c',
  dependencies: core_plugin_dep,
  c_args: daemon_c_flags,
  link_with: libnms_ifupdown_core,
  link_args: ldflags_linker_script_settings,
  link_depends: linker_script_settings,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_settings_plugin_ifupdown

if enable_tests
  subdir('tests')
endif
