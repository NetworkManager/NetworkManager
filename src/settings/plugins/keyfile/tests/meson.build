test_unit = 'test-keyfile'

test_keyfiles_dir = join_paths(meson.current_source_dir(), 'keyfiles')

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
)

test(
  'keyfile/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
