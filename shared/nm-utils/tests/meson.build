test_unit = 'test-shared-general'

exe = executable(
  test_unit,
  test_unit + '.c',
  c_args: [
    '-DNETWORKMANAGER_COMPILATION_TEST',
    '-DNETWORKMANAGER_COMPILATION=(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)',
  ],
  dependencies: [
    shared_nm_glib_aux_dep,
    libnm_systemd_shared_no_logging_dep,
    shared_c_siphash_dep,
  ],
)

test(
  'shared/nm-utils/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
