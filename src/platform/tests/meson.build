test_fake_c_flags = test_c_flags + ['-DSETUP=nm_fake_platform_setup']
test_linux_c_flags = test_c_flags + ['-DSETUP=nm_linux_platform_setup']

test_units = [
  ['test-address-fake', 'test-address.c', test_fake_c_flags, default_test_timeout],
  ['test-address-linux', 'test-address.c', test_linux_c_flags, default_test_timeout],
  ['test-cleanup-fake', 'test-cleanup.c', test_fake_c_flags, default_test_timeout],
  ['test-cleanup-linux', 'test-cleanup.c', test_linux_c_flags, default_test_timeout],
  ['test-link-fake', 'test-link.c', test_fake_c_flags, default_test_timeout],
  ['test-link-linux', 'test-link.c', test_linux_c_flags, 900],
  ['test-nmp-object', 'test-nmp-object.c', test_c_flags, default_test_timeout],
  ['test-platform-general', 'test-platform-general.c', test_c_flags, default_test_timeout],
  ['test-route-fake', 'test-route.c', test_fake_c_flags, default_test_timeout],
  ['test-route-linux', 'test-route.c', test_linux_c_flags, default_test_timeout],
]

foreach test_unit: test_units
  exe = executable(
    test_unit[0],
    test_unit[1],
    dependencies: libnetwork_manager_test_dep,
    c_args: test_unit[2],
  )
  test(
    'platform/' + test_unit[0],
    test_script,
    timeout: test_unit[3],
    args: test_args + [exe.full_path()],
  )
endforeach

name = 'monitor'

executable(
  name,
  name + '.c',
  dependencies: libnetwork_manager_test_dep,
  c_args: test_c_flags,
)
