sources = files(
  'nm-device-contrail-vrouter.c',
  'nm-contrail-factory.c'
)

deps = [
  nm_dep
]

libnm_device_plugin_contrail = shared_module(
  'nm-device-plugin-contrail',
  sources: sources,
  dependencies: deps,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir
)

core_plugins += libnm_device_plugin_contrail

test(
  'check-local-devices-contrail',
  check_exports,
  args: [libnm_device_plugin_contrail.full_path(), linker_script_devices],
)

# FIXME: check_so_symbols replacement
'''
check-local-devices-contrail: src/devices/contrail/libnm-device-plugin-contrail.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/contrail/.libs/libnm-device-plugin-contrail.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/contrail/.libs/libnm-device-plugin-contrail.so)
'''
