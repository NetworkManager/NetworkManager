test_unit = 'test-ifcfg-rh'

test_ifcfg_dir = meson.current_source_dir()

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: nm_build_cflags,
  link_with: libnms_ifcfg_rh_core
)

test(
  'ifcfg-rh/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()]
)
