sources = files(
  'nms-ifnet-connection-parser.c',
  'nms-ifnet-net-parser.c',
  'nms-ifnet-net-utils.c',
  'nms-ifnet-wpa-parser.c'
)

cflags = [
  '-DSBINDIR="@0@"'.format(nm_sbindir),
  '-DSYSCONFDIR="@0@"'.format(nm_sysconfdir)
]

libnms_ifnet_core = static_library(
  'nms-ifnet-core',
  sources: sources,
  dependencies: core_dep,
  c_args: cflags
)

sources = files(
  'nms-ifnet-connection.c',
  'nms-ifnet-plugin.c'
)

ldflags = []
if have_version_script
  ldflags += '-Wl,--version-script,@0@'.format(linker_script_settings)
endif

libnm_settings_plugin_ifnet = shared_module(
  'nm-settings-plugin-ifnet',
  sources: sources,
  dependencies: core_dep,
  c_args: cflags,
  link_with: libnms_ifnet_core,
  link_args: ldflags,
  link_depends: linker_script_settings,
  install: true,
  install_dir: nm_pkglibdir
)

core_plugins += libnm_settings_plugin_ifnet

# FIXME: check_so_symbols replacement
'''
run_target(
  'check-local-symbols-settings-ifnet',
  command: [check_so_symbols, libnm_settings_plugin_ifnet.full_path()],
  depends: libnm_settings_plugin_ifnet
)

check-local-symbols-settings-ifnet: src/settings/plugins/ifnet/libnm-settings-plugin-ifnet.la
  $(call check_so_symbols,$(builddir)/src/settings/plugins/ifnet/.libs/libnm-settings-plugin-ifnet.so)
'''

if enable_tests
  subdir('tests')
endif
