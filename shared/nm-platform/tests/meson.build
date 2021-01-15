# SPDX-License-Identifier: LGPL-2.1-or-later

exe = executable(
  'test-nm-platform',
  'test-nm-platform.c',
  c_args: [
    '-DNETWORKMANAGER_COMPILATION_TEST',
    '-DNETWORKMANAGER_COMPILATION=(NM_NETWORKMANAGER_COMPILATION_GLIB|NM_NETWORKMANAGER_COMPILATION_WITH_GLIB_I18N_PROG)',
  ],
  dependencies: [
    libnm_log_core_dep,
    libnm_platform_dep,
  ],
)

test(
  'shared/nm-glib-aux/test-nm-platform',
  test_script,
  args: test_args + [exe.full_path()],
  timeout: default_test_timeout,
)
