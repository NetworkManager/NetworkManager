incs = [
  top_inc,
  shared_inc
]

deps = [
  dbus_dep,
  dbus_glib_dep,
  glib_dep,
  libnm_util_dep
]

cflags = [
  '-DBUILD_DIR="@0@"'.format(meson.current_source_dir()),
  '-DTEST_CERT_DIR="@0@"'.format(test_cert_dir)
]

test = 'test-libnm-linking'

test_libnm_linking = executable(
  test,
  [test + '.c', libnm_utils_enums_h],
  include_directories: incs,
  dependencies: deps + [libnm_dep],
  c_args: cflags
)

test_units = [
  ['test-crypto', [libtest_crypto], []],
  ['test-general', [], [test_libnm_linking]],
  ['test-secrets', [], []],
  ['test-setting-8021x', [], []],
  ['test-setting-dcb', [], []],
  ['test-settings-defaults', [], []]
]

foreach test_unit: test_units
  name = 'libnm-utils-' + test_unit[0]

  exe = executable(
    name,
    [test_unit[0] + '.c', libnm_utils_enums_h],
    include_directories: incs,
    dependencies: deps,
    c_args: cflags,
    link_with: test_unit[1],
    link_depends: test_unit[2]
  )

  test(name, exe)
endforeach
