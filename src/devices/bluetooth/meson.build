# SPDX-License-Identifier: LGPL-2.1-or-later

libnm_device_plugin_bluetooth_static = static_library(
  'nm-device-plugin-bluetooth-static',
  sources: files(
    'nm-bluez-manager.c',
    'nm-bt-error.c',
    'nm-device-bt.c',
  ) + (enable_bluez5_dun ? files('nm-bluez5-dun.c') : files()),
  dependencies: [
    core_default_dep,
    libnm_wwan_dep,
    bluez5_dep,
  ],
  c_args: daemon_c_flags,
)

libnm_device_plugin_bluetooth_static_dep = declare_dependency(
  link_whole: libnm_device_plugin_bluetooth_static,
)

libnm_device_plugin_bluetooth = shared_module(
  'nm-device-plugin-bluetooth',
  dependencies: [
    core_plugin_dep,
    libnm_wwan_dep,
    bluez5_dep,
    libnm_device_plugin_bluetooth_static_dep,
  ],
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
  args: [
    libnm_device_plugin_bluetooth.full_path(),
    linker_script_devices
  ],
)

if enable_tests
  executable(
    'nm-bt-test',
    'tests/nm-bt-test.c',
    dependencies: [
      libNetworkManagerTest_dep,
      core_default_dep,
      libnm_wwan_dep,
      bluez5_dep,
      libnm_device_plugin_bluetooth_static_dep,
    ],
    c_args: test_c_flags,
  )
endif
