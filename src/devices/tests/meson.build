# SPDX-License-Identifier: LGPL-2.1-or-later

test_units = [
  'test-acd',
  'test-lldp',
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: libNetworkManagerTest_dep,
    c_args: test_c_flags,
  )

  test(
    'devices/' + test_unit,
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endforeach
