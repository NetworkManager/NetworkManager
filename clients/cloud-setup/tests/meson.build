# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-cloud-setup-general',
  'test-cloud-setup-general.c',
  dependencies: [
    libnm_cloud_setup_core_dep,
    libnmc_base_dep,
    libnmc_dep,
    glib_dep,
  ],
  link_with: [
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'clients/cloud-setup/tests/test-cloud-setup-general',
  test_script,
  args: test_args + [exe.full_path()],
)
