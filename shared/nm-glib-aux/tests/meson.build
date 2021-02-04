# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-shared-general',
  'test-shared-general.c',
  c_args: [
    '-DG_LOG_DOMAIN="test"',
  ],
  dependencies: libnm_glib_aux_dep,
  link_with: libnm_systemd_logging_stub,
)

test(
  'shared/nm-glib-aux/test-shared-general',
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)

if jansson_dep.found()
  exe = executable(
    'test-json-aux',
    'test-json-aux.c',
    c_args: [
      '-DG_LOG_DOMAIN="test"',
    ],
    dependencies: [
      libnm_glib_aux_dep,
      jansson_dep,
      dl_dep,
    ],
    link_with: libnm_systemd_logging_stub,
  )

  test(
    'shared/nm-glib-aux/test-json-aux',
    test_script,
    args: test_args + [exe.full_path()],
    timeout: default_test_timeout,
  )
endif
