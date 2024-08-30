# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-libnm-core-utils',
  'test-libnm-core-utils.c',
    include_directories: [
      libnm_core_aux_intern_inc
  ],
  link_with: [
    libnm_core_aux_intern,
    libnm_core_impl,
    libnm_base,
    libnm_crypto,
    libnm_systemd_shared,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  dependencies: [
    libnm_client_public_dep,
    libnm_core_public_dep,
    uuid_dep,
    glib_dep,
    dl_dep,
  ],
)

test(
  'src/libnm-core-aux-intern/tests/test-libnm-core-utils',
  exe,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
