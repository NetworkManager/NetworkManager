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
      nm_test_utils_impl_source,
    ],
    dependencies: liblibnm_dep,
    c_args: cflags,
    link_with: [
      liblibnm,
      libnm_core,
      libnm_systemd_logging_stub,
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
  sources: nm_vpn_plugin_utils_source + [libnm_enum[1]],
  include_directories: libnm_inc,
  dependencies: libnm_core_dep,
  c_args: cflags,
)
