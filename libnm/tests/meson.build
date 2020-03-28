# SPDX-License-Identifier: LGPL-2.1+

test_units = [
  ['test-libnm', 30],
  ['test-nm-client', 90],
  ['test-remote-settings-client', 90],
  ['test-secret-agent', 90],
]

deps = [
  libnm_core_dep,
  libnm_nm_default_dep,
]

c_flags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM',
]

foreach test_unit: test_units
  exe = executable(
    test_unit[0],
    [test_unit[0] + '.c', nm_test_utils_impl_source, libnm_enum_sources[1]],
    dependencies: deps,
    c_args: c_flags,
    link_with: liblibnm,
  )

  test(
    test_unit[0],
    test_script,
    timeout: test_unit[1],
    args: test_args + [exe.full_path()],
  )
endforeach

# just test, that we can build "nm-vpn-plugin-utils.c"
libnm_vpn_plugin_utils_test = static_library(
  'nm-vpn-plugin-utils-test',
  sources: nm_vpn_plugin_utils_source + [libnm_enum_sources[1]],
  include_directories: libnm_inc,
  dependencies: libnm_nm_default_dep,
  c_args: c_flags,
)
