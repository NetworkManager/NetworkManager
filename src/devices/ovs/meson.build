sources = files(
  'nm-device-ovs-bridge.c',
  'nm-device-ovs-interface.c',
  'nm-device-ovs-port.c',
  'nm-ovsdb.c',
  'nm-ovs-factory.c'
)

deps = [
  jansson_dep,
  nm_dep
]

libnm_device_plugin_ovs = shared_module(
  'nm-device-plugin-ovs',
  sources: sources,
  dependencies: deps,
  c_args: '-DRUNSTATEDIR="@0@"'.format(nm_runstatedir),
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir
)

core_plugins += libnm_device_plugin_ovs

run_target(
  'check-local-devices-ovs',
  command: [check_exports, libnm_device_plugin_ovs.full_path(), linker_script_devices],
  depends: libnm_device_plugin_ovs
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-ovs: src/devices/ovs/libnm-device-plugin-ovs.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/ovs/.libs/libnm-device-plugin-ovs.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/ovs/.libs/libnm-device-plugin-ovs.so)
'''
