# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-cloud-setup-general',
  'test-cloud-setup-general.c',
  dependencies: [
    libnm_cloud_setup_core_dep,
    libnmc_base_dep,
    libnmc_dep,
    libnm_glib_aux_dep_link,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="test"',
  ],
)

test(
  'clients/cloud-setup/tests/test-cloud-setup-general',
  test_script,
  args: test_args + [exe.full_path()],
)
