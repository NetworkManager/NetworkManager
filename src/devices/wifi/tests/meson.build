test_unit = 'test-general'

exe = executable(
  'wifi-' + test_unit,
  [test_unit + '.c'] + common_sources,
  dependencies: test_core_dep
)

test(test_unit, exe)
