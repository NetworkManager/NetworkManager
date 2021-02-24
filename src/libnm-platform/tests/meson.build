# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-nm-platform',
  'test-nm-platform.c',
  dependencies: [
    libnm_platform_dep,
    glib_dep,
  ],
  include_directories: [
    src_inc,
    top_inc,
  ],
  link_with: [
    libnm_log_core,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'shared/nm-glib-aux/test-nm-platform',
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
