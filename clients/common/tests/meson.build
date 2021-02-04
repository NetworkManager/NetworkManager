# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-clients-common',
  'test-clients-common.c',
  dependencies: [
    libnmc_base_dep,
    libnmc_dep,
  ],
  c_args: [
    '-DNETWORKMANAGER_COMPILATION_TEST',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
)

test(
  'clients/common/tests/test-clients-common',
  test_script,
  args: test_args + [exe.full_path()],
)

exe = executable(
  'test-libnm-core-aux',
  'test-libnm-core-aux.c',
  dependencies: [
    libnm_dep,
    libnm_libnm_core_aux_dep,
    libnm_nm_default_dep,
  ],
  c_args: [
    '-DNETWORKMANAGER_COMPILATION_TEST',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ],
  link_with: libnm_systemd_logging_stub,
)

test(
  'clients/common/tests/test-libnm-core-aux',
  test_script,
  args: test_args + [exe.full_path()]
)
