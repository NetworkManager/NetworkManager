# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-nm-platform',
  'test-nm-platform.c',
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
    libudev_dep,
  ],
  link_with: [
    libnm_platform,
    libnm_base,
    libnm_udev_aux,
    libnm_log_core,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'src/libnm-platform/tests/test-nm-platform',
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
