# SPDX-License-Identifier: LGPL-2.1-or-later

libnmi_core = static_library(
  'nmi-core',
  sources: files(
    'nmi-cmdline-reader.c',
    'nmi-dt-reader.c',
    'nmi-ibft-reader.c',
  ),
  dependencies: core_default_dep,
)

executable(
  'nm-initrd-generator',
  'nm-initrd-generator.c',
  dependencies: core_default_dep,
  link_with: [
    libNetworkManagerBase,
    libnmi_core,
    libnm_core_impl,
    libnm_platform,
    libnm_base,
    libnm_systemd_shared,
    libnm_log_core,
    libnm_udev_aux,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
