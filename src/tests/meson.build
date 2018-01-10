subdir('config')

test_units = [
  'test-general',
  'test-general-with-expect',
  'test-ip4-config',
  'test-ip6-config',
  'test-dcb',
  'test-resolvconf-capture',
  'test-wired-defname',
  'test-utils'
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: test_nm_dep
  )

  test(test_unit, exe)
endforeach

test_unit = 'test-systemd'

cflags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD',
]

exe = executable(
  test_unit,
  [test_unit + '.c'] + shared_siphash,
  include_directories: src_inc,
  dependencies: nm_core_dep,
  c_args: cflags,
  link_with: libsystemd_nm
)

test(test_unit, exe)
