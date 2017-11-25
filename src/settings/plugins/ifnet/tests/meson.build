test_unit = 'test-ifnet'

test_ifnet_dir = meson.current_source_dir()

cflags = [
  '-DSYSCONFDIR="nonexistent"',
  '-DTEST_IFNET_DIR="@0@"'.format(test_ifnet_dir),
  '-DTEST_SCRATCH_DIR="@0@"'.format(test_ifnet_dir),
  '-DTEST_WPA_SUPPLICANT_CONF="@0@"'.format(join_paths(test_ifnet_dir, 'wpa_supplicant.conf'))
]

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_core_dep,
  c_args: cflags,
  link_with: libnms_ifnet_core
)

test(test_unit, exe)
