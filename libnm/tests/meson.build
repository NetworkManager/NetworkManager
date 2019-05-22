test_units = [
  ['test-libnm',                  30],
  ['test-nm-client',              90],
  ['test-remote-settings-client', 90],
  ['test-secret-agent',           90],
]

cflags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_LIBNM',
]

foreach test_unit: test_units
  exe = executable(
    test_unit[0],
    [
      test_unit[0] + '.c',
      shared_nm_test_utils_impl_c,
    ],
    dependencies: [
      liblibnm_dep,
      libnm_systemd_shared_no_logging_dep,
    ],
    c_args: cflags,
    link_with: [
      liblibnm,
      libnm_core,
    ],
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
  sources: shared_nm_utils_nm_vpn_plugin_utils_c + [libnm_enum[1]],
  include_directories: libnm_inc,
  dependencies: libnm_core_dep,
  c_args: cflags,
)
