sources = files(
  'nm-device-team.c',
  'nm-team-factory.c',
)

deps = [
  daemon_nm_default_dep,
  jansson_dep,
  libteamdctl_dep,
]

libnm_device_plugin_team = shared_module(
  'nm-device-plugin-team',
  sources: sources,
  dependencies: deps,
  c_args: daemon_c_flags,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_device_plugin_team

test(
  'check-local-devices-team',
  check_exports,
  args: [libnm_device_plugin_team.full_path(), linker_script_devices],
)
