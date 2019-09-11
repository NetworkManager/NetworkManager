test_unit = 'test-ifcfg-rh'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: libnetwork_manager_test_dep,
  c_args: test_c_flags,
  link_with: libnms_ifcfg_rh_core,
)

test(
  'ifcfg-rh/' + test_unit,
  test_script,
  timeout: 90,
  args: test_args + [exe.full_path()],
)
