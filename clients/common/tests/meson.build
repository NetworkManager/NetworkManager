test_unit = 'test-general'

name = 'client-' + test_unit

deps += [
  libnmc_dep,
  libnmc_base_dep
]

exe = executable(
  name,
  test_unit + '.c',
  include_directories: incs,
  dependencies: deps,
  c_args: cflags
)

test(name, exe)
