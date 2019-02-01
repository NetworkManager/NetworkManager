deps = [
  dbus_dep,
  dbus_glib_dep,
  libnm_glib_dep,
  libnm_util_dep,
  shared_nm_utils_base_dep,
]

test_units = [
  'test-nm-client',
  'test-remote-settings-client',
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    [test_unit + '.c'] + shared_nm_test_utils_impl_c,
    dependencies: deps,
    c_args:
      common_cflags + [
        '-DNETWORKMANAGER_COMPILATION_TEST',
      ],
  )

  test(
    'libnm-glib/' + test_unit,
    test_script,
    args: test_args + [exe.full_path()],
  )
endforeach
