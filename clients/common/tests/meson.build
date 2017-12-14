test_unit = 'test-general'

deps += [
  libnmc_dep,
  libnmc_base_dep
]

exe = executable(
  'clients-' + test_unit,
  test_unit + '.c',
  include_directories: incs,
  dependencies: deps,
  c_args: cflags
)

test(test_unit, exe)
