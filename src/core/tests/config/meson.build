# SPDX-License-Identifier: LGPL-2.1-or-later

test_config_dir = meson.current_source_dir()

test_unit = 'test-config'

sources = files(
  'nm-test-device.c',
  'test-config.c',
)

exe = executable(
  test_unit,
  sources,
  dependencies: libNetworkManagerTest_dep,
  c_args: test_c_flags,
)

test(
  'config/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
