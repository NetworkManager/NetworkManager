test_unit = 'test-config'

sources = files(
  'nm-test-device.c',
  'test-config.c',
)

test_config_dir = meson.current_source_dir()

exe = executable(
  test_unit,
  sources,
  dependencies: test_nm_dep,
)

test(
  'config/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
