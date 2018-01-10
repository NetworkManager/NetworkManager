deps = [
  dbus_dep,
  dbus_glib_dep,
  libnm_glib_dep,
  libnm_util_dep,
  shared_dep
]

test_units = [
  # FIXME: these tests currently fail
  #'test-nm-client',
  #'test-remote-settings-client'
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    [test_unit + '.c'] + shared_test_utils,
    dependencies: deps,
    c_args: common_cflags + [
      '-DNETWORKMANAGER_COMPILATION_TEST',
      '-DTEST_NM_SERVICE="@0@"'.format(join_paths(meson.source_root(), 'tools', 'test-networkmanager-service.py')),
    ],
  )

  test(test_unit, exe)
endforeach
