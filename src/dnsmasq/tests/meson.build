test_unit = 'test-dnsmasq-utils'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: libnetwork_manager_test_dep,
  c_args: test_c_flags,
)

test(
  'dnsmasq/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
