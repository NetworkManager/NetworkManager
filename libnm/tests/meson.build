test_units = [
  ['test-general', shared_utils, [libnm_utils]],
  # FIXME: these tests fails usually
  #['test-nm-client', shared_test_utils, []],
  #['test-remote-settings-client',  shared_test_utils, []],
  #['test-secret-agent', shared_test_utils, []]
]

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc
]

deps = [
  glib_dep,
  libnm_dep
]

cflags = [
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIB',
  '-DTEST_NM_SERVICE="@0@"'.format(join_paths(meson.source_root(), 'tools', 'test-networkmanager-service.py'))
]

foreach test_unit: test_units
  name = 'libnm-' + test_unit[0]

  exe = executable(
    name,
    [test_unit[0] + '.c'] + test_unit[1],
    include_directories: incs,
    dependencies: deps,
    c_args: cflags,
    link_with: test_unit[2]
  )

  test(name, exe)
endforeach

incs = [
  top_inc,
  shared_inc,
  libnm_core_inc,
  libnm_inc
]

# just test, that we can build "nm-vpn-plugin-utils.c"
libnm_vpn_plugin_utils_test = static_library(
  'nm-vpn-plugin-utils-test',
  sources: shared_vpn_plugin_utils + [libnm_enums_h],
  include_directories: incs,
  dependencies: glib_dep
)
