# SPDX-License-Identifier: LGPL-2.1+

common_c_flags = clients_c_flags + ['-DNETWORKMANAGER_COMPILATION_TEST']

test_name = 'test-clients-common'

deps = [
  libnmc_base_dep,
  libnmc_dep,
]

exe = executable(
  test_name,
  test_name + '.c',
  dependencies: deps,
  c_args: common_c_flags,
)

test(
  'clients/common/tests/' + test_name,
  test_script,
  args: test_args + [exe.full_path()],
)

test_name = 'test-libnm-core-aux'

deps = [
  libnm_dep,
  libnm_libnm_core_aux_dep,
  libnm_nm_default_dep,
]

exe = executable(
  test_name,
  test_name + '.c',
  dependencies: deps,
  c_args: common_c_flags,
  link_with: libnm_systemd_logging_stub,
)

test(
  'clients/common/tests/' + test_name,
  test_script,
  args: test_args + [exe.full_path()]
)
