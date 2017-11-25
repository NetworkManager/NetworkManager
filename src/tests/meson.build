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
  name = 'tests-' + test_unit

  exe = executable(
    name,
    test_unit + '.c',
    dependencies: test_core_dep
  )

  test(name, exe)
endforeach

test_unit = 'test-systemd'
name = 'tests-' + test_unit

cflags = '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD'

exe = executable(
  name,
  [test_unit + '.c', libnm_core_enums_h] + shared_siphash,
  include_directories: core_incs,
  dependencies: glib_dep,
  c_args: cflags,
  link_with: libsystemd_nm
)

test(name, exe)
