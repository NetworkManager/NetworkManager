name = 'nm-settings-plugin-ibft'

libnms_ibft_core = static_library(
  'nms-ibft-core',
  'nms-ibft-reader.c',
  dependencies: nm_dep,
)

sources = files(
  'nms-ibft-connection.c',
  'nms-ibft-plugin.c',
)

libnm_settings_plugin_ibft = shared_module(
  name,
  sources: sources,
  dependencies: nm_dep,
  link_with: libnms_ibft_core,
  link_args: ldflags_linker_script_settings,
  link_depends: linker_script_settings,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_settings_plugin_ibft

# FIXME: check_so_symbols replacement
'''
run_target(
  'check-local-symbols-settings-ibft',
  command: [check_so_symbols, libnm_settings_plugin_ibft.full_path()],
  depends: libnm_settings_plugin_ibft,
)

check-local-symbols-settings-ibft: src/settings/plugins/ibft/libnm-settings-plugin-ibft.la
  $(call check_so_symbols,$(builddir)/src/settings/plugins/ibft/.libs/libnm-settings-plugin-ibft.so)
'''

if enable_tests
  subdir('tests')
endif
