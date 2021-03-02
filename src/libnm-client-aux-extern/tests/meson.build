# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-libnm-client-aux',
  'test-libnm-client-aux.c',
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
  link_with: [
    libnm_core_aux_extern,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'src/libnm-client-aux-extern/tests/test-libnm-client-aux',
  test_script,
  args: test_args + [exe.full_path()]
)
