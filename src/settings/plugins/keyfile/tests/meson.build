# SPDX-License-Identifier: LGPL-2.1-or-later

test_unit = 'test-keyfile-settings'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: libNetworkManagerTest_dep,
  c_args: test_c_flags,
)

test(
  test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
