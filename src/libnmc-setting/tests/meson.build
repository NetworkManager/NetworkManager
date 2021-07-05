# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-libnmc-setting',
  'test-libnmc-setting.c',
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
  link_with: [
    libnmc_setting,
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
  'src/libnmc-setting/tests/test-libnmc-setting',
  test_script,
  args: test_args + [exe.full_path()],
)
