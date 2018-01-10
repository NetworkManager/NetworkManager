test_unit = 'test-ibft'

test_ibft_dir = meson.current_source_dir()

cflags = [
  '-DTEST_IBFT_DIR="@0@"'.format(test_ibft_dir),
  '-DTEST_SCRATCH_DIR="@0@"'.format(test_ibft_dir)
]

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: cflags,
  link_with: libnms_ibft_core
)

test(test_unit, exe)
