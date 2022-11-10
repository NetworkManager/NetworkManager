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
      libnm_core_public_dep,
      libnm_client_public_dep,
      glib_dep,
      libudev_dep,
    ],
    link_with: [
      libnm_client_impl,
      libnm_client_test,
      libnm_core_aux_intern,
      libnm_core_impl,
      libnm_crypto,
      libnm_base,
      libnm_udev_aux,
      libnm_systemd_shared,
      libnm_log_null,
      libnm_glib_aux,
      libnm_std_aux,
      libc_siphash,
      libnmdbus,
    ],
  )

  test(
    'src/libnm-client-impl/tests/' + test_unit,
    test_script,
    timeout: 90,
    args: test_args + [exe.full_path()],
  )
endforeach

if enable_introspection
  test(
    'check-local-libnm-gir',
    python,
    args: [
      join_paths(meson.source_root(), 'src', 'libnm-client-impl', 'tests', 'test-gir.py'),
      '--gir', libnm_gir[0],
      '--ver', join_paths(meson.source_root(), 'src', 'libnm-client-impl', 'libnm.ver'),
    ],
  )
endif
