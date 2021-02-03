# SPDX-License-Identifier: LGPL-2.1-or-later

libnmi_core = static_library(
  'nmi-core',
  sources: files(
    'nmi-cmdline-reader.c',
    'nmi-dt-reader.c',
    'nmi-ibft-reader.c',
  ),
  dependencies: core_default_dep,
  c_args: daemon_c_flags,
)

executable(
  'nm-initrd-generator',
  'nm-initrd-generator.c',
  dependencies: core_default_dep,
  c_args: daemon_c_flags,
  link_with: [
    libNetworkManagerBase,
    libnmi_core,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
