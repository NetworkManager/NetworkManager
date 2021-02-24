# SPDX-License-Identifier: LGPL-2.1-or-later

test_units = [
  'test-libnm',
  'test-nm-client',
  'test-remote-settings-client',
  'test-secret-agent',
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    [ test_unit + '.c' ] + (test_unit == 'test-libnm' ? src_contrib_nm_compat_source : []),
    include_directories: [
      libnm_client_public_inc,
    ],
    dependencies: [
      libnm_core_impl_dep_link,
      libnm_nm_default_dep,
      glib_dep,
    ],
    link_with: [
      libnm_client_impl,
      libnm_client_test,
      libnm_base,
      libnm_glib_aux,
      libnm_std_aux,
      libc_siphash,
      libnmdbus,
    ],
  )

  test(
    test_unit,
    test_script,
    timeout: 90,
    args: test_args + [exe.full_path()],
  )
endforeach
