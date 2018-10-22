test_units = [
  ['test-link-fake',     'test-link.c',       test_nm_dep_fake,  30],
  ['test-link-linux',    'test-link.c',       test_nm_dep_linux, 180],
  ['test-address-fake',  'test-address.c',    test_nm_dep_fake,  30],
  ['test-address-linux', 'test-address.c',    test_nm_dep_linux, 30],
  ['test-general',       'test-general.c',    test_nm_dep,       30],
  ['test-nmp-object',    'test-nmp-object.c', test_nm_dep,       30],
  ['test-route-fake',    'test-route.c',      test_nm_dep_fake,  30],
  ['test-route-linux',   'test-route.c',      test_nm_dep_linux, 30],
  ['test-cleanup-fake',  'test-cleanup.c',    test_nm_dep_fake,  30],
  ['test-cleanup-linux', 'test-cleanup.c',    test_nm_dep_linux, 30],
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
    args: test_args + [exe.full_path()]
  )
endforeach

test = 'monitor'

executable(
  test,
  test + '.c',
  dependencies: test_nm_dep,
)
