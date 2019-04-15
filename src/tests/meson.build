subdir('config')

test_units = [
  'test-general',
  'test-general-with-expect',
  'test-ip4-config',
  'test-ip6-config',
  'test-dcb',
  'test-wired-defname',
  'test-utils',
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    test_unit + '.c',
    dependencies: test_nm_dep,
  )

  test(
    'src/' + test_unit,
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endforeach

test_unit = 'test-systemd'

cflags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD',
]

exe = executable(
  test_unit,
  [test_unit + '.c'],
  include_directories: src_inc,
  dependencies: libnm_core_dep,
  c_args: cflags,
  link_with: [
    libnm_systemd_core,
    libnm_systemd_shared,
  ],
)

test(
  'src/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
