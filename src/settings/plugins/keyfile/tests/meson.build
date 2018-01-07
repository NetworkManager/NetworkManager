test_unit = 'test-keyfile'

test_keyfiles_dir = join_paths(meson.current_source_dir(), 'keyfiles')

cflags = [
  '-DTEST_KEYFILES_DIR="@0@"'.format(test_keyfiles_dir),
  '-DTEST_SCRATCH_DIR="@0@"'.format(test_keyfiles_dir)
]

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: cflags
)

test(test_unit, exe)
