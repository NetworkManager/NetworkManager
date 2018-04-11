test_unit = 'test-ndisc-fake'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: test_cflags_platform
)

test(
  'ndisc/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()]
)

test = 'test-ndisc-linux'

exe = executable(
  test,
  test + '.c',
  dependencies: test_nm_dep,
  c_args: test_cflags_platform
)
