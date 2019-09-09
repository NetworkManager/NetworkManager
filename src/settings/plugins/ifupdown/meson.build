sources = files(
  'nms-ifupdown-interface-parser.c',
  'nms-ifupdown-parser.c',
)

libnms_ifupdown_core = static_library(
  'nms-ifupdown-core',
  sources: sources,
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
)

sources = files(
  'nms-ifupdown-plugin.c',
)

libnm_settings_plugin_ifupdown = shared_module(
  'nm-settings-plugin-ifupdown',
  sources: sources,
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
  link_with: libnms_ifupdown_core,
  link_args: ldflags_linker_script_settings,
  link_depends: linker_script_settings,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_settings_plugin_ifupdown

# FIXME: check_so_symbols replacement
'''
run_target(
  'check-local-symbols-settings-ifupdown',
  command: [check_so_symbols, libnm_settings_plugin_ifupdown.full_path()],
  depends: libnm_settings_plugin_ifupdown,
)

check-local-symbols-settings-ifupdown: src/settings/plugins/ifupdown/libnm-settings-plugin-ifupdown.la
  $(call check_so_symbols,$(builddir)/src/settings/plugins/ifupdown/.libs/libnm-settings-plugin-ifupdown.so)
'''

if enable_tests
  subdir('tests')
endif
