common_sources = files(
  'nm-wifi-ap.c',
  'nm-wifi-utils.c'
)

sources = common_sources + files(
  'nm-wifi-factory.c',
  'nm-wifi-common.c',
  'nm-device-wifi.c',
  'nm-device-olpc-mesh.c'
)

if enable_iwd
  sources += files(
    'nm-device-iwd.c',
    'nm-iwd-manager.c',
  )
endif

deps = [
  nm_dep
]

libnm_device_plugin_wifi = shared_module(
  'nm-device-plugin-wifi',
  sources: sources,
  dependencies: deps,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir
)

core_plugins += libnm_device_plugin_wifi

run_target(
  'check-local-devices-wifi',
  command: [check_exports, libnm_device_plugin_wifi.full_path(), linker_script_devices],
  depends: libnm_device_plugin_wifi
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-wifi: src/devices/wifi/libnm-device-plugin-wifi.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/wifi/.libs/libnm-device-plugin-wifi.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/wifi/.libs/libnm-device-plugin-wifi.so)
'''

if enable_tests
  subdir('tests')
endif
