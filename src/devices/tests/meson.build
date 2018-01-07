test_units = [
  'test-arping',
  'test-lldp'
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: test_nm_dep
  )

  test(test_unit, exe)
endforeach
