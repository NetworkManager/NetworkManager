# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-ifupdown',
  'test-ifupdown.c',
  dependencies: libNetworkManagerTest_dep,
  c_args: test_c_flags,
  link_with: libnms_ifupdown_core,
)

test(
  'ifupdown/test-ifupdown',
  test_script,
  args: test_args + [exe.full_path()],
)
