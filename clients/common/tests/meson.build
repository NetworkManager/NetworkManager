test_name = 'test-clients-common'

exe = executable(
  test_name,
  test_name + '.c',
  dependencies: [
    libnm_dep,
    libnmc_dep,
    libnmc_base_dep,
    libnm_nm_default_dep,
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

deps = [
  libnm_dep,
  libnm_libnm_core_aux_dep,
  libnm_nm_default_dep,
]

exe = executable(
    'test-libnm-core-aux',
    [ 'test-libnm-core-aux.c', ],
    c_args: [
        '-DNETWORKMANAGER_COMPILATION_TEST',
        '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
    ],
    dependencies: deps,
    link_with: libnm_systemd_logging_stub,
)

test(
    'clients/common/tests/test-libnm-core-aux',
    test_script,
    args: test_args + [exe.full_path()]
)
