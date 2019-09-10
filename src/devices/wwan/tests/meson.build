exe = executable(
  'test-service-providers',
  sources: files('test-service-providers.c',
                 '../nm-service-providers.c'),
  include_directories: wwan_inc,
  dependencies: libnetwork_manager_test_dep,
  c_args: test_c_flags,
)
test(
  'wwan/test-service-providers',
  test_script,
  timeout: default_test_timeout,
  args: test_args + [exe.full_path()],
)
