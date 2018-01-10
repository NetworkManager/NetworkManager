test_unit = 'test-ifupdown'

cflags = '-DTEST_ENI_DIR="@0@"'.format(meson.current_source_dir())

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: cflags,
  link_with: libnms_ifupdown_core
)

test(test_unit, exe)
