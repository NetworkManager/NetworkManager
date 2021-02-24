# SPDX-License-Identifier: LGPL-2.1-or-later

executable(
  'nm-dhcp-helper',
  'nm-dhcp-helper.c',
  include_directories: [
    src_inc,
    top_inc,
  ],
  dependencies: glib_dep,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
