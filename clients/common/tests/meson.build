# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-clients-common',
  'test-clients-common.c',
  dependencies: [
    libnmc_base_dep,
    libnmc_dep,
    libnm_core_aux_intern_dep_link,
    libnm_core_aux_extern_dep_link,
    libnm_glib_aux_dep_link,
    libnm_base_dep_link,
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
    libnm_core_aux_extern_dep_link,
    libnm_nm_default_dep,
    libnm_glib_aux_dep_link,
  ],
  link_with: libnm_log_null,
)

test(
  'clients/common/tests/test-libnm-core-aux',
  test_script,
  args: test_args + [exe.full_path()]
)
