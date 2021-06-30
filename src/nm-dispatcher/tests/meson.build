# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-dispatcher-envp',
  [
    'test-dispatcher-envp.c',
    dispatcher_nmdbus_dispatcher_sources,
  ],
  dependencies: [
    libnm_dep,
    glib_dep,
  ],
  c_args: introspection_extra_cflags,
  link_with: [
    libnm_dispatcher_core,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
)

test(
  'src/nm-dispatcher/tests/test-dispatcher-envp',
  test_script,
  args: test_args + [exe.full_path()],
)
