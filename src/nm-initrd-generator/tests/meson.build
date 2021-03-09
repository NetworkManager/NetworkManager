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
    include_directories: [
      src_inc,
      top_inc,
    ],
    dependencies: [
      libnm_core_public_dep,
    ],
    c_args: test_c_flags,
    link_with: [
      libnmi_core,
      libnm_core_aux_intern,
      libnm_core_impl,
      libnm_crypto,
      libnm_platform,
      libnm_base,
      libnm_systemd_shared,
      libnm_udev_aux,
      libnm_log_core,
      libnm_glib_aux,
      libnm_std_aux,
      libc_siphash,
    ],
  )

  test(
    'nm-initrd-generator/tests/' + test_unit,
    test_script,
    timeout: default_test_timeout,
    args: test_args + [exe.full_path()],
  )
endforeach
