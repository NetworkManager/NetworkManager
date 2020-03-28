# SPDX-License-Identifier: LGPL-2.1+

test_unit = 'test-shared-general'

c_flags = [
  '-DNETWORKMANAGER_COMPILATION_TEST',
  '-DNETWORKMANAGER_COMPILATION=(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)',
]

exe = executable(
  test_unit,
  test_unit + '.c',
  c_args: c_flags,
  dependencies: libnm_utils_base_dep,
  link_with: libnm_systemd_logging_stub,
)

test(
  'shared/nm-glib-aux/' + test_unit,
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
