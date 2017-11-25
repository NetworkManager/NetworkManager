test_units = [
  'test-ndisc-fake',
  'test-ndisc-linux'
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: test_core_dep,
    c_args: test_cflags_platform
  )

  test(test_unit, exe)
endforeach
