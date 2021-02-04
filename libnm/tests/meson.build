# SPDX-License-Identifier: LGPL-2.1-or-later

test_units = [
  'test-libnm',
  'test-nm-client',
  'test-remote-settings-client',
  'test-secret-agent',
]

foreach test_unit: test_units
  exe = executable(
    test_unit,
    [
      test_unit + '.c',
      nm_test_utils_impl_source,
      libnm_enum_sources[1],
    ],
    dependencies: [
      libnm_core_dep,
      libnm_nm_default_dep,
    ],
    c_args: [
      '-DNETWORKMANAGER_COMPILATION_TEST',
      '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM',
    ],
    link_with: libnm_static,
  )

  test(
    test_unit,
    test_script,
    timeout: 90,
    args: test_args + [exe.full_path()],
  )
endforeach

# just test, that we can build "nm-vpn-plugin-utils.c"
libnm_vpn_plugin_utils_test = static_library(
  'nm-vpn-plugin-utils-test',
  sources: nm_vpn_plugin_utils_source + [libnm_enum_sources[1]],
  include_directories: libnm_inc,
  dependencies: libnm_nm_default_dep,
  c_args: [
    '-DG_LOG_DOMAIN="test"',
  ],
)
