# SPDX-License-Identifier: LGPL-2.1-or-later

if install_systemdunitdir

  nm_cloud_setup_service = configure_file(
    input: 'nm-cloud-setup.service.in',
    output: '@BASENAME@',
    install_dir: systemd_systemdsystemunitdir,
    configuration: data_conf,
  )

  install_data(
    'nm-cloud-setup.timer',
    install_dir: systemd_systemdsystemunitdir,
  )

  install_data(
    '90-nm-cloud-setup.sh',
    install_dir: join_paths(nm_pkglibdir, 'dispatcher.d', 'no-wait.d'),
  )

endif

libnm_cloud_setup_core = static_library(
  'nm-cloud-setup-core',
  sources: files(
    'nm-cloud-setup-utils.c',
    'nm-http-client.c',
    'nmcs-provider-ec2.c',
    'nmcs-provider-gcp.c',
    'nmcs-provider-azure.c',
    'nmcs-provider.c',
  ),
  dependencies: [
    libnmc_base_dep,
    libnmc_dep,
    libcurl_dep,
    libnm_libnm_aux_dep,
  ],
)

libnm_cloud_setup_core_dep = declare_dependency(
  include_directories: include_directories('.'),
  link_with: libnm_cloud_setup_core,
)

executable(
  'nm-cloud-setup',
  files(
    'main.c',
  ),
  dependencies: [
    libnm_cloud_setup_core_dep,
    libnmc_base_dep,
    libnmc_dep,
    libnm_core_aux_intern_dep_link,
    libnm_core_aux_extern_dep_link,
    libnm_glib_aux_dep_link,
    libcurl_dep,
  ],
  link_with: libnm_log_null,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  subdir('tests')
endif
