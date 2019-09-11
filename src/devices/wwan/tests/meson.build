test_unit = 'test-service-providers'

exe = executable(
  test_unit,
  [test_unit + '.c'] + nm_service_providers_source,
  include_directories: wwan_inc,
  dependencies: libnetwork_manager_test_dep,
  c_args: test_c_flags,
)

test(
  'wwan/' + test_unit,
  test_script,
  timeout: default_test_timeout,
  args: test_args + [exe.full_path()],
)
