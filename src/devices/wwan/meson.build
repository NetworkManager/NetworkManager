sources = files(
  'nm-modem-broadband.c',
  'nm-modem.c',
  'nm-modem-manager.c'
)

deps = [
  libsystemd_dep,
  mm_glib_dep,
  nm_dep
]

if enable_ofono
  sources += files('nm-modem-ofono.c')
endif

linker_script = join_paths(meson.current_source_dir(), 'libnm-wwan.ver')

libnm_wwan = shared_module(
  'nm-wwan',
  sources: sources,
  dependencies: deps,
  link_args: [
    '-Wl,--version-script,@0@'.format(linker_script),
  ],
  link_depends: linker_script,
  install: true,
  install_dir: nm_plugindir
)

libnm_wwan_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: libnm_wwan
)

core_plugins += libnm_wwan

run_target(
  'check-wwan',
  command: [check_exports, libnm_wwan.full_path(), linker_script],
  depends: libnm_wwan
)

sources = files(
  'nm-device-modem.c',
  'nm-wwan-factory.c'
)

libnm_device_plugin_wwan = shared_module(
  'nm-device-plugin-wwan',
  sources: sources,
  dependencies: deps,
  link_with: libnm_wwan,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir
)

core_plugins += libnm_device_plugin_wwan

run_target(
  'check-local-devices-wwan',
  command: [check_exports, libnm_device_plugin_wwan.full_path(), linker_script_devices],
  depends: libnm_device_plugin_wwan
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-wwan: src/devices/wwan/libnm-device-plugin-wwan.la src/devices/wwan/libnm-wwan.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/wwan/.libs/libnm-device-plugin-wwan.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/wwan/.libs/libnm-device-plugin-wwan.so)
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/wwan/.libs/libnm-wwan.so "$(srcdir)/src/devices/wwan/libnm-wwan.ver"
  $(call check_so_symbols,$(builddir)/src/devices/wwan/.libs/libnm-wwan.so)
'''
