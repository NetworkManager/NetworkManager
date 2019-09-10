subdir('config')

test_units = [
  'test-core',
  'test-core-with-expect',
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
    dependencies: libnetwork_manager_test_dep,
    c_args: test_c_flags,
  )

  test(
    test_unit,
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endforeach

test_unit = 'test-systemd'

c_flags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_SYSTEMD',
]

links = [
  libnm_systemd_core,
  libnm_systemd_shared,
]

exe = executable(
  test_unit,
  test_unit + '.c',
  dependencies: daemon_nm_default_dep,
  c_args: c_flags,
  link_with: links,
)

test(
  test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
