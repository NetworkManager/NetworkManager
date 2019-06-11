test_name = 'test-clients-common'

exe = executable(
  test_name,
  test_name + '.c',
  dependencies: [
    libnm_dep,
    libnmc_dep,
    libnmc_base_dep,
    libnm_core_dep,
  ],
  c_args: clients_cflags + [
    '-DNETWORKMANAGER_COMPILATION_TEST',
  ],
)

test(
  test_name,
  test_script,
  args: test_args + [exe.full_path()],
)

###############################################################################

exe = executable(
    'test-libnm-core-aux',
    [ 'test-libnm-core-aux.c', ],
    c_args: [
        '-DNETWORKMANAGER_COMPILATION_TEST',
        '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
    ],
    dependencies: [
        libnm_dep,
        shared_nm_libnm_core_aux_dep,
        shared_nm_libnm_core_intern_dep,
    ],
)

test(
    'clients/common/tests/test-libnm-core-aux',
    test_script,
    args: test_args + [exe.full_path()]
)
