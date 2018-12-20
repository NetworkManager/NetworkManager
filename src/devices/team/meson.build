sources = files(
  'nm-device-team.c',
  'nm-team-factory.c',
)

deps = [
  jansson_dep,
  libteamdctl_dep,
  nm_dep,
]

libnm_device_plugin_team = shared_module(
  'nm-device-plugin-team',
  sources: sources,
  dependencies: deps,
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

# FIXME: check_so_symbols replacement
'''
check-local-devices-team: src/devices/team/libnm-device-plugin-team.la
  $(srcdir)/tools/check-exports.sh $(builddir)/src/devices/team/.libs/libnm-device-plugin-team.so "$(srcdir)/linker-script-devices.ver"
  $(call check_so_symbols,$(builddir)/src/devices/team/.libs/libnm-device-plugin-team.so)
'''
