test_unit = 'test-devices-wifi'

exe = executable(
  test_unit,
  [test_unit + '.c'] + common_sources,
  dependencies: test_nm_dep,
)

test(
  test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
