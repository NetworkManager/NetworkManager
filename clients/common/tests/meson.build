test_unit = 'test-general'

deps = [
  libnm_dep,
  libnmc_dep,
  libnmc_base_dep,
  nm_core_dep,
]

exe = executable(
  'clients-' + test_unit,
  test_unit + '.c',
  dependencies: deps,
  c_args: clients_cflags + [
    '-DNETWORKMANAGER_COMPILATION_TEST',
  ],
)

test(
  'clients/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
