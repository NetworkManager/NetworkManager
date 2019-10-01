test_unit = 'test-dispatcher-envp'

deps = [
  libnm_nm_default_dep,
  libnm_utils_base_dep,
]

c_flags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
]

exe = executable(
  test_unit,
  [test_unit + '.c', nmdbus_dispatcher_sources],
  include_directories: dispatcher_inc,
  dependencies: deps,
  c_args: c_flags,
  link_with: libnm_dispatcher_core,
)

test(
  'dispatcher/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
