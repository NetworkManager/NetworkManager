# SPDX-License-Identifier: LGPL-2.1-or-later

subdir('config')

test_units = [
  'test-core',
  'test-core-with-expect',
  'test-dcb',
  'test-ip4-config',
  'test-ip6-config',
  'test-l3cfg',
  'test-utils',
  'test-wired-defname',
]

foreach test_unit: test_units
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
endforeach

exe = executable(
  'test-systemd',
  'test-systemd.c',
  include_directories: [
    top_inc,
    src_inc,
    src_core_inc,
  ],
  dependencies: [
    libnm_core_public_dep,
    libnm_systemd_core_dep,
  ],
  link_with: [
    libnm_systemd_shared,
    libc_siphash,
  ],
)

test(
  'test-systemd',
  test_script,
  args: test_args + [exe.full_path()],
)
