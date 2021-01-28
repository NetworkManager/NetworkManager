# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-keyfile-settings',
  'test-keyfile-settings.c',
  dependencies: libNetworkManagerTest_dep,
  c_args: test_c_flags,
)

test(
  'test-keyfile-settings',
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
