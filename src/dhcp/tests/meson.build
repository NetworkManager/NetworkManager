test_units = [
  'test-dhcp-dhclient',
  'test-dhcp-utils'
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: test_nm_dep,
    c_args: nm_build_cflags,
  )

  test(
    'dhcp/' + test_unit,
    test_script,
    args: test_args + [exe.full_path()]
  )
endforeach
