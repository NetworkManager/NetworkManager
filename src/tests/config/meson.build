test_unit = 'test-config'

sources = files(
  'nm-test-device.c',
  'test-config.c'
)

test_config_dir = meson.current_source_dir()

exe = executable(
  test_unit,
  sources,
  dependencies: test_nm_dep,
  c_args: nm_build_cflags,
)

test(
  'config/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()]
)
