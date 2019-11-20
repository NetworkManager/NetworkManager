test_unit = 'test-ifupdown'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: libnetwork_manager_test_dep,
  c_args: test_c_flags,
  link_with: libnms_ifupdown_core,
)

test(
  'ifupdown/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
