# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-dispatcher-envp',
  [
    'test-dispatcher-envp.c',
    nmdbus_dispatcher_sources,
  ],
  include_directories: dispatcher_inc,
  dependencies: [
    libnm_nm_default_dep,
    libnm_glib_aux_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="test"',
  ] + introspection_extra_cflags,
  link_with: libnm_dispatcher_core,
)

test(
  'dispatcher/test-dispatcher-envp',
  test_script,
  args: test_args + [exe.full_path()],
)
