test_units = [
  ['test-general', shared_utils, [libnm_utils]],
  # FIXME: these tests fails usually
  #['test-nm-client', shared_test_utils, []],
  #['test-remote-settings-client',  shared_test_utils, []],
  #['test-secret-agent', shared_test_utils, []]
]

deps = [
  libnm_dep,
  nm_core_dep
]

cflags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM',
  '-DTEST_NM_SERVICE="@0@"'.format(join_paths(meson.source_root(), 'tools', 'test-networkmanager-service.py'))
]

foreach test_unit: test_units
  exe = executable(
    'libnm-' + test_unit[0],
    [test_unit[0] + '.c'] + test_unit[1],
    dependencies: deps,
    c_args: cflags,
    link_with: test_unit[2]
  )

  test(test_unit[0], exe)
endforeach

# just test, that we can build "nm-vpn-plugin-utils.c"
libnm_vpn_plugin_utils_test = static_library(
  'nm-vpn-plugin-utils-test',
  sources: shared_vpn_plugin_utils + [libnm_enum[1]],
  include_directories: libnm_inc,
  dependencies: nm_core_dep,
  c_args: cflags
)
