# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-shared-general',
  'test-shared-general.c',
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
  ],
  link_with: [
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'src/libnm-glib-aux/tests/test-shared-general',
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)

if jansson_dep.found()
  exe = executable(
    'test-json-aux',
    'test-json-aux.c',
    dependencies: [
      glib_dep,
      jansson_dep,
      dl_dep,
    ],
    include_directories: [
      src_inc,
      top_inc,
    ],
    link_with: [
      libnm_log_null,
      libnm_glib_aux,
      libnm_std_aux,
      libc_siphash,
    ],
  )

  test(
    'src/libnm-glib-aux/tests/test-json-aux',
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endif
