test_unit = 'test-dnsmasq-utils'

cflags = '-DTESTDIR="@0@"'.format(meson.source_root())

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: test_core_dep,
  c_args: cflags
)

test(test_unit, exe)
