test_unit = 'test-dnsmasq-utils'

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_nm_dep,
  c_args: '-DTESTDIR="@0@"'.format(meson.source_root())
)

test(
  test_unit,
  test_script,
  args: test_args + [exe.full_path()]
)
