test_units = [
  ['test-link-fake',     'test-link.c',       test_nm_dep_fake,  default_test_timeout],
  ['test-link-linux',    'test-link.c',       test_nm_dep_linux, 900],
  ['test-address-fake',  'test-address.c',    test_nm_dep_fake,  default_test_timeout],
  ['test-address-linux', 'test-address.c',    test_nm_dep_linux, default_test_timeout],
  ['test-general',       'test-general.c',    test_nm_dep,       default_test_timeout],
  ['test-nmp-object',    'test-nmp-object.c', test_nm_dep,       default_test_timeout],
  ['test-route-fake',    'test-route.c',      test_nm_dep_fake,  default_test_timeout],
  ['test-route-linux',   'test-route.c',      test_nm_dep_linux, default_test_timeout],
  ['test-cleanup-fake',  'test-cleanup.c',    test_nm_dep_fake,  default_test_timeout],
  ['test-cleanup-linux', 'test-cleanup.c',    test_nm_dep_linux, default_test_timeout],
]

foreach test_unit: test_units
  exe = executable(
    'platform-' + test_unit[0],
    test_unit[1],
    dependencies: test_unit[2],
  )

  test(
    'platform/' + test_unit[0],
    test_script,
    timeout: test_unit[3],
    args: test_args + [exe.full_path()],
  )
endforeach

test = 'monitor'

executable(
  test,
  test + '.c',
  dependencies: test_nm_dep,
)
