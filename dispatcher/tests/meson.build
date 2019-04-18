test_unit = 'test-dispatcher-envp'

incs = [
  dispatcher_inc,
  libnm_inc,
]

exe = executable(
  test_unit,
  test_unit + '.c',
  include_directories: incs,
  dependencies: libnm_core_dep,
  c_args: [
      '-DNETWORKMANAGER_COMPILATION_TEST',
      '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
    ],
  link_with: libnm_dispatcher_core,
)

test(
  'dispatcher/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
