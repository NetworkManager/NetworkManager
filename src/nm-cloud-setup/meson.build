# SPDX-License-Identifier: LGPL-2.1-or-later

if install_systemdunitdir

  nm_cloud_setup_service = configure_file(
    input: 'nm-cloud-setup.service.in',
    output: '@BASENAME@',
    install_dir: systemd_systemdsystemunitdir,
    configuration: data_conf,
  )

  test(
    'check-nm-cloud-setup.service',
    find_program(join_paths(source_root, 'src/tests/check-systemd-unit.sh')),
    args: [ join_paths(meson.current_build_dir(), 'nm-cloud-setup.service') ],
  )

  install_data(
    'nm-cloud-setup.timer',
    install_dir: systemd_systemdsystemunitdir,
  )

  install_data(
    '90-nm-cloud-setup.sh',
    install_dir: join_paths(nm_pkglibdir, 'dispatcher.d', 'pre-up.d'),
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
    'nmcs-provider-aliyun.c',
    'nmcs-provider-oci.c',
    'nmcs-provider.c',
  ),
  dependencies: [
    libnm_dep,
    glib_dep,
    libcurl_dep,
    jansson_dep,
  ],
)

executable(
  'nm-cloud-setup',
  files(
    'main.c',
  ),
  dependencies: [
    libnm_dep,
    glib_dep,
    libcurl_dep,
  ],
  link_with: [
    libnm_cloud_setup_core,
    libnmc_base,
    libnm_client_aux_extern,
    libnm_core_aux_extern,
    libnm_core_aux_intern,
    libnm_log_null,
    libnm_glib_aux,
    libnm_std_aux,
    libc_siphash,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)
