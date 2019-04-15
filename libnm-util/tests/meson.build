deps = [
  dbus_dep,
  dbus_glib_dep,
  libnm_util_dep,
  shared_nm_glib_aux_dep,
]

cflags = common_cflags + [
  '-DNETWORKMANAGER_COMPILATION_TEST',
]

test = 'test-libnm-linking'

test_libnm_linking = executable(
  test,
  test + '.c',
  dependencies: deps + [libnm_dep],
  c_args: cflags,
)

test_units = [
  ['test-crypto', [libtest_crypto], []],
  ['test-general', [], [test_libnm_linking]],
  ['test-secrets', [], []],
  ['test-setting-8021x', [], []],
  ['test-setting-dcb', [], []],
  ['test-settings-defaults', [], []],
]

foreach test_unit: test_units
  exe = executable(
    'libnm-util-' + test_unit[0],
    test_unit[0] + '.c',
    dependencies: deps,
    c_args: cflags,
    link_with: test_unit[1],
    link_depends: test_unit[2],
  )

  test(
    'libnm-util/' + test_unit[0],
    test_script,
    args: test_args + [exe.full_path()],
  )
endforeach
