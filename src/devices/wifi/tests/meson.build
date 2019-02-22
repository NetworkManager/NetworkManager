test_unit = 'test-general'

exe = executable(
  'wifi-' + test_unit,
  [test_unit + '.c'] + common_sources,
  dependencies: test_nm_dep,
)

test(
  'devices/wifi/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
