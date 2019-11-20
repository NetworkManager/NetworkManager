test_unit = 'test-keyfile-settings'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: libnetwork_manager_test_dep,
  c_args: test_c_flags,
)

test(
  test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
