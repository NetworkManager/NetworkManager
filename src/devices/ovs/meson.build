# SPDX-License-Identifier: LGPL-2.1+

sources = files(
  'nm-device-ovs-bridge.c',
  'nm-device-ovs-interface.c',
  'nm-device-ovs-port.c',
  'nm-ovsdb.c',
  'nm-ovs-factory.c',
)

deps = [
  daemon_nm_default_dep,
  jansson_dep,
]

libnm_device_plugin_ovs = shared_module(
  'nm-device-plugin-ovs',
  sources: sources,
  dependencies: deps,
  c_args: daemon_c_flags,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_device_plugin_ovs

test(
  'check-local-devices-ovs',
  check_exports,
  args: [libnm_device_plugin_ovs.full_path(), linker_script_devices],
)
