# SPDX-License-Identifier: LGPL-2.1-or-later

test_unit = 'test-dispatcher-envp'

exe = executable(
  test_unit,
  [test_unit + '.c', nmdbus_dispatcher_sources],
  include_directories: dispatcher_inc,
  dependencies: [
    libnm_nm_default_dep,
    libnm_glib_aux_dep,
  ],
  c_args: [
    '-DNETWORKMANAGER_COMPILATION_TEST',
    '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_CLIENT',
  ] + introspection_extra_cflags,
  link_with: libnm_dispatcher_core,
)

test(
  'dispatcher/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
)
