# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-ifcfg-rh',
  'test-ifcfg-rh.c',
  dependencies: libNetworkManagerTest_dep,
  c_args: test_c_flags,
  link_with: libnms_ifcfg_rh_core,
)

test(
  'ifcfg-rh/test-ifcfg-rh',
  test_script,
  timeout: 90,
  args: test_args + [exe.full_path()],
)
