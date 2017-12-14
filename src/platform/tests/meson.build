test_units = [
  ['test-link-fake', 'test-link.c'],
  ['test-link-linux', 'test-link.c'],
  ['test-address-fake', 'test-address.c'],
  ['test-address-linux', 'test-address.c'],
  ['test-general', 'test-general.c'],
  ['test-nmp-object', 'test-nmp-object.c'],
  ['test-route-fake', 'test-route.c'],
  ['test-route-linux', 'test-route.c'],
  ['test-cleanup-fake', 'test-cleanup.c'],
  ['test-cleanup-linux', 'test-cleanup.c'],
]

foreach test_unit: test_units
  exe = executable(
    'platform-' + test_unit[0],
    test_unit[1],
    dependencies: test_core_dep,
    c_args: test_cflags_platform
  )

  test(test_unit[0], exe)
endforeach

test = 'monitor'

executable(
  test,
  test + '.c',
  dependencies: test_core_dep,
  c_args: test_cflags_platform
)
