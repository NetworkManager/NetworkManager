sources = files(
  'nm-atm-manager.c',
  'nm-device-adsl.c',
)

libnm_device_plugin_adsl = shared_module(
  'nm-device-plugin-adsl',
  sources: sources,
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
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
