test_unit = 'test-config'

sources = files(
  'nm-test-device.c',
  'test-config.c'
)

test_config_dir = meson.current_source_dir()

cflags = [
  '-DSRCDIR="@0@"'.format(test_config_dir),
  '-DBUILDDIR="@0@"'.format(test_config_dir)
]

exe = executable(
  test_unit,
  sources,
  dependencies: test_nm_dep,
  c_args: cflags
)

test(test_unit, exe)
