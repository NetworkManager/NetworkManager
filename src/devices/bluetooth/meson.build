sources = files(
  'nm-bluez-manager.c',
  'nm-bt-error.c',
  'nm-device-bt.c',
)

deps = [
  daemon_nm_default_dep,
  libnm_wwan_dep,
]

if enable_bluez5_dun
  sources += files('nm-bluez5-dun.c')

  deps += bluez5_dep
endif

libnm_device_plugin_bluetooth = shared_module(
  'nm-device-plugin-bluetooth',
  sources: sources,
  dependencies: deps,
  c_args: daemon_c_flags,
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
