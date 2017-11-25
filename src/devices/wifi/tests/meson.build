test_unit = 'test-general'

name = 'wifi-' + test_unit

exe = executable(
  name,
  [test_unit + '.c'] + common_sources,
  dependencies: test_core_dep
)

test(name, exe)
