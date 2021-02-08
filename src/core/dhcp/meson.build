# SPDX-License-Identifier: LGPL-2.1+

name = 'nm-dhcp-helper'

c_flags = [
  '-DG_LOG_DOMAIN="@0@"'.format(name),
  '-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_GLIB',
]

executable(
  name,
  name + '.c',
  dependencies: glib_nm_default_dep,
  c_args: c_flags,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
