sources = files(
  'nm-bluez-device.c',
  'nm-bluez-manager.c',
  'nm-bluez4-adapter.c',
  'nm-bluez4-manager.c',
  'nm-bluez5-manager.c',
  'nm-bt-error.c',
  'nm-device-bt.c',
)

deps = [
  libnm_wwan_dep,
  nm_dep,
]

if enable_bluez5_dun
  sources += files('nm-bluez5-dun.c')

  deps += bluez5_dep
endif

libnm_device_plugin_bluetooth = shared_module(
  'nm-device-plugin-bluetooth',
  sources: sources,
  dependencies: deps,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
  install_rpath: nm_plugindir,
)

core_plugins += libnm_device_plugin_bluetooth

test(
  'check-local-devices-bluetooth',
  check_exports,
  args: [libnm_device_plugin_bluetooth.full_path(), linker_script_devices],
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-bluetooth: src/devices/bluetooth/libnm-device-plugin-bluetooth.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/bluetooth/.libs/libnm-device-plugin-bluetooth.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/bluetooth/.libs/libnm-device-plugin-bluetooth.so)
'''
