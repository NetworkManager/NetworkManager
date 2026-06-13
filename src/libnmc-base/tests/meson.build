# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-client-utils',
  'test-client-utils.c',
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
  link_with: [
    libnmc_base,
    libnm_core_aux_extern,
    libnm_core_aux_intern,
    libnm_base,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'src/libnmc-base/tests/test-client-utils',
  test_script,
  args: test_args + [exe.full_path()],
)
