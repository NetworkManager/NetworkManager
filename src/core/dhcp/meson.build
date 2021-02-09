# SPDX-License-Identifier: LGPL-2.1-or-later

executable(
  'nm-dhcp-helper',
  'nm-dhcp-helper.c',
  dependencies: glib_nm_default_dep,
  c_args: [
    '-DG_LOG_DOMAIN="nm-dhcp-helper"',
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
