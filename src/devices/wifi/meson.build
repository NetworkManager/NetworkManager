common_sources = files(
  'nm-wifi-ap.c',
  'nm-wifi-p2p-peer.c',
  'nm-wifi-utils.c',
)

sources = common_sources + files(
  'nm-device-olpc-mesh.c',
  'nm-device-wifi-p2p.c',
  'nm-device-wifi.c',
  'nm-wifi-common.c',
  'nm-wifi-factory.c',
)

if enable_iwd
  sources += files(
    'nm-device-iwd.c',
    'nm-iwd-manager.c',
  )
endif

libnm_device_plugin_wifi = shared_module(
  'nm-device-plugin-wifi',
  sources: sources,
  dependencies: daemon_nm_default_dep,
  c_args: daemon_c_flags,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
)

core_plugins += libnm_device_plugin_wifi

test(
  'check-local-devices-wifi',
  check_exports,
  args: [libnm_device_plugin_wifi.full_path(), linker_script_devices],
)

if enable_tests
  subdir('tests')
endif
