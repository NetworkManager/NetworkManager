data_conf = configuration_data()
data_conf.set('bindir', nm_bindir)
data_conf.set('libexecdir', nm_libexecdir)
data_conf.set('sbindir', nm_sbindir)
data_conf.set('sysconfdir', nm_sysconfdir)
data_conf.set('DISTRO_NETWORK_SERVICE', (enable_ifcfg_rh ? 'network.service' : ''))
data_conf.set('NM_MODIFY_SYSTEM_POLICY', (enable_modify_system ? 'yes' : 'auth_admin_keep'))

server = 'server.conf'

configure_file(
  input: server + '.in',
  output: server,
  install: true,
  install_dir: join_paths(nm_datadir, 'doc', nm_name, 'examples'),
  configuration: data_conf,
)

if install_systemd_unit_dir
  services = [
    'NetworkManager-dispatcher.service',
    'NetworkManager.service',
  ]

  if have_systemd_200
    services += ['NetworkManager-wait-online.service']
  else
    services += ['NetworkManager-wait-online-systemd-pre200.service']
  endif

  foreach service: services
    configure_file(
      input: service + '.in',
      output: service,
      install: true,
      install_dir: systemd_system_unit_dir,
      configuration: data_conf,
    )
  endforeach

  if enable_ovs
    install_data(
      'NetworkManager-ovs.conf',
      install_dir: join_paths(systemd_system_unit_dir, 'NetworkManager.service.d'),
    )
  endif
endif

if install_udev_dir
  data = files(
    '84-nm-drivers.rules',
    '85-nm-unmanaged.rules',
    '90-nm-thunderbolt.rules',
  )

  install_data(
    data,
    install_dir: join_paths(udev_dir, 'rules.d'),
  )
endif

if enable_polkit
  policy = 'org.freedesktop.NetworkManager.policy'

  policy_in = configure_file(
    input: policy + '.in.in',
    output: policy + '.in',
    configuration: data_conf,
  )

  custom_target(
    policy,
    input: policy_in,
    output: policy,
    command: intltool_xml_cmd,
    install: true,
    install_dir: polkit_dir,
  )
endif
