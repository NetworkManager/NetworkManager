test_unit = 'test-supplicant-config'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: '-DTEST_CERT_DIR="@0@"'.format(join_paths(meson.current_source_dir(), 'certs'))
)

test(test_unit, exe)
