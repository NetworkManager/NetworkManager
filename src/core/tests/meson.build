# SPDX-License-Identifier: LGPL-2.1-or-later

subdir('config')

test_units = [
  'test-core',
  'test-core-with-expect',
  'test-dcb',
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
  ],
  dependencies: [
    libnm_systemd_shared_dep_inc,
    libnm_systemd_core_dep_inc,
    glib_dep,
  ],
  link_with: [
    libnm_systemd_shared,
    libnm_systemd_core,
    libnm_glib_aux,
    libnm_log_null,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'test-systemd',
  test_script,
  args: test_args + [exe.full_path()],
)
