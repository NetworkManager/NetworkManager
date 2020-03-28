# SPDX-License-Identifier: LGPL-2.1+

configure_file(
  input: 'server.conf.in',
  output: '@BASENAME@',
  install_dir: join_paths(nm_datadir, 'doc', nm_name, 'examples'),
  configuration: data_conf,
)

if install_systemdunitdir
  services = [
    'NetworkManager-dispatcher.service.in',
    'NetworkManager.service.in',
  ]

  if have_systemd_200
    services += ['NetworkManager-wait-online.service.in']
  else
    services += ['NetworkManager-wait-online-systemd-pre200.service.in']
  endif

  foreach service: services
    configure_file(
      input: service,
      output: '@BASENAME@',
      install_dir: systemd_systemdsystemunitdir,
      configuration: data_conf,
    )
  endforeach

  if enable_ovs
    install_data(
      'NetworkManager-ovs.conf',
      install_dir: join_paths(systemd_systemdsystemunitdir, 'NetworkManager.service.d'),
    )
  endif
endif

if install_udevdir
  data = files(
    '84-nm-drivers.rules',
    '85-nm-unmanaged.rules',
    '90-nm-thunderbolt.rules',
  )

  install_data(
    data,
    install_dir: join_paths(udev_udevdir, 'rules.d'),
  )
endif

if enable_polkit
  policy = 'org.freedesktop.NetworkManager.policy'

  policy_in = configure_file(
    input: policy + '.in.in',
    output: '@BASENAME@',
    configuration: data_conf,
  )

  custom_target(
    policy,
    input: policy_in,
    output: '@BASENAME@',
    command: intltool_xml_cmd,
    install: true,
    install_dir: polkit_gobject_policydir,
  )
endif
