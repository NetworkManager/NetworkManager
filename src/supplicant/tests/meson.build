test_unit = 'test-supplicant-config'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
)

test(
  'supplicant/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
