test_units = [
  'test-dhcp-dhclient',
  'test-dhcp-utils'
]

cflags = '-DTESTDIR="@0@"'.format(meson.current_source_dir())

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: test_core_dep,
    c_args: cflags
  )

  test(test_unit, exe)
endforeach
