test_unit = 'test-ifcfg-rh'

test_ifcfg_dir = meson.current_source_dir()

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  link_with: libnms_ifcfg_rh_core,
)

test(
  'ifcfg-rh/' + test_unit,
  test_script,
  timeout: 90,
  args: test_args + [exe.full_path()],
)
