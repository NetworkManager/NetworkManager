test_unit = 'test-ndisc-fake'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: test_cflags_platform
)

test(test_unit, exe)

test = 'test-ndisc-linux'

exe = executable(
  test,
  test + '.c',
  dependencies: test_nm_dep,
  c_args: test_cflags_platform
)
