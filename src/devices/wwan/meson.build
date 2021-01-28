# SPDX-License-Identifier: LGPL-2.1-or-later

wwan_inc = include_directories('.')

linker_script = join_paths(meson.current_source_dir(), 'libnm-wwan.ver')

libnm_wwan = shared_module(
  'nm-wwan',
  sources: files(
  'nm-service-providers.c',
  'nm-modem-broadband.c',
  'nm-modem.c',
  'nm-modem-manager.c',
  ) + (enable_ofono ? files('nm-modem-ofono.c') : files()),
  dependencies: [
    core_plugin_dep,
    libsystemd_dep,
    mm_glib_dep,
  ],
  c_args: daemon_c_flags,
  link_args: '-Wl,--version-script,@0@'.format(linker_script),
  link_depends: linker_script,
  install: true,
  install_dir: nm_plugindir,
)

libnm_wwan_dep = declare_dependency(
  include_directories: wwan_inc,
  link_with: libnm_wwan,
)

core_plugins += libnm_wwan

test(
  'check-wwan',
  check_exports,
  args: [
    libnm_wwan.full_path(),
    linker_script,
  ],
)

libnm_device_plugin_wwan = shared_module(
  'nm-device-plugin-wwan',
  sources: files(
    'nm-device-modem.c',
    'nm-wwan-factory.c',
  ),
  dependencies: [
    core_plugin_dep,
    libsystemd_dep,
    mm_glib_dep,
  ],
  c_args: daemon_c_flags,
  link_with: libnm_wwan,
  link_args: ldflags_linker_script_devices,
  link_depends: linker_script_devices,
  install: true,
  install_dir: nm_plugindir,
  install_rpath: nm_plugindir,
)

core_plugins += libnm_device_plugin_wwan

run_target(
  'check-local-devices-wwan',
  command: [check_exports, libnm_device_plugin_wwan.full_path(), linker_script_devices],
  depends: libnm_device_plugin_wwan,
)

if enable_tests
  exe = executable(
    'test-service-providers',
    files(
      'tests/test-service-providers.c',
      'nm-service-providers.c',
    ),
    include_directories: wwan_inc,
    dependencies: libNetworkManagerTest_dep,
    c_args: test_c_flags,
  )
  test(
    'wwan/test-service-providers',
    test_script,
    timeout: default_test_timeout,
    args: test_args + [exe.full_path()],
  )
endif
