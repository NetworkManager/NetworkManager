test_unit = 'test-ndisc-fake'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep_fake,
)

test(
  'ndisc/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)

test = 'test-ndisc-linux'

exe = executable(
  test,
  test + '.c',
  dependencies: test_nm_dep_linux,
)
