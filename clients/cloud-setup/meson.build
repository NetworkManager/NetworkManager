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

executable(
  'nm-cloud-setup',
  files(
    'main.c',
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
  c_args: [
    '-DG_LOG_DOMAIN="nm-cloud-setup"',
  ],
  link_with: libnm_systemd_logging_stub,
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)
