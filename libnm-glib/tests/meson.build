incs = [
  top_inc,
  shared_inc
]

deps = [
  dbus_dep,
  dbus_glib_dep,
  glib_dep,
  libnm_glib_dep,
  libnm_util_dep
]

cflags = [
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB_LEGACY',
  '-DTEST_NM_SERVICE="@0@"'.format(join_paths(meson.source_root(), 'tools', 'test-networkmanager-service.py'))
]

test_units = [
  'test-nm-client',
  'test-remote-settings-client'
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    [test_unit + '.c', libnm_utils_enum[1]] + shared_test_utils,
    include_directories: incs,
    dependencies: deps,
    c_args: cflags
  )

  test(test_unit, exe)
endforeach
