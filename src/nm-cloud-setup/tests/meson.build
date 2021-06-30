# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-cloud-setup-general',
  'test-cloud-setup-general.c',
  dependencies: [
    libnm_dep,
    glib_dep,
    libcurl_dep,
  ],
  link_with: [
    libnm_cloud_setup_core,
    libnmc_base,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'src/nm-cloud-setup/tests/test-cloud-setup-general',
  test_script,
  args: test_args + [exe.full_path()],
)
