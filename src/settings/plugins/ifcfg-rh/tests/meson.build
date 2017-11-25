test_unit = 'test-ifcfg-rh'

test_ifcfg_dir = meson.current_source_dir()

cflags = [
  '-DTEST_IFCFG_DIR="@0@"'.format(test_ifcfg_dir),
  '-DTEST_SCRATCH_DIR="@0@"'.format(test_ifcfg_dir)
]

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_core_dep,
  c_args: cflags,
  link_with: libnms_ifcfg_rh_core
)

test(test_unit, exe)
