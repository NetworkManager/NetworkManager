# SPDX-License-Identifier: LGPL-2.1-or-later

test_units = [
  'test-dt-reader',
  'test-ibft-reader',
  'test-cmdline-reader',
]

foreach test_unit : test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: libNetworkManagerTest_dep,
    c_args: test_c_flags,
    link_with: libnmi_core,
  )

  test(
    'initrd/' + test_unit,
    test_script,
    timeout: default_test_timeout,
    args: test_args + [exe.full_path()],
  )
endforeach
