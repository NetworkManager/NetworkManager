sources = files(
  'nm-atm-manager.c',
  'nm-device-adsl.c',
)

deps = [
  libudev_dep,
  nm_dep,
]

libnm_device_plugin_adsl = shared_module(
  'nm-device-plugin-adsl',
  sources: sources,
  dependencies: deps,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_device_plugin_adsl

test(
  'check-local-devices-adsl',
  check_exports,
  args: [libnm_device_plugin_adsl.full_path(), linker_script_devices],
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-adsl: src/devices/adsl/libnm-device-plugin-adsl.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/adsl/.libs/libnm-device-plugin-adsl.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/adsl/.libs/libnm-device-plugin-adsl.so)
'''
