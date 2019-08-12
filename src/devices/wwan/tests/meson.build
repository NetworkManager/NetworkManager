exe = executable(
  'test-service-providers',
  sources: files('test-service-providers.c',
                 '../nm-service-providers.c'),
  dependencies: test_nm_dep,
  include_directories: wwan_inc,
)
test(
  'wwan/test-service-providers',
  test_script,
  timeout: default_test_timeout,
  args: test_args + [exe.full_path()],
)
