# SPDX-License-Identifier: LGPL-2.1-or-later

test_unit = 'test-dnsmasq-utils'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: libNetworkManagerTest_dep,
  c_args: test_c_flags,
)

test(
  'dnsmasq/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
