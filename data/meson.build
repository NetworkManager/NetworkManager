# SPDX-License-Identifier: LGPL-2.1-or-later

configure_file(
  input: 'server.conf.in',
  output: '@BASENAME@',
  install_dir: join_paths(nm_datadir, 'doc', nm_name, 'examples'),
  configuration: data_conf,
)

if install_systemdunitdir
  services = [
    'NetworkManager-dispatcher.service',
    'NetworkManager.service',
    'nm-priv-helper.service',
    'NetworkManager-wait-online.service',
    'NetworkManager-config-initrd.service',
    'NetworkManager-initrd.service',
    'NetworkManager-wait-online-initrd.service',
  ]

  foreach service: services
    configure_file(
      input: service + '.in',
      output: service,
      install_dir: systemd_systemdsystemunitdir,
      configuration: data_conf,
    )

    test(
      'check-' + service,
      find_program(join_paths(source_root, 'src/tests/check-systemd-unit.sh')),
      args: [ join_paths(meson.current_build_dir(), service) ],
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
  i18n.merge_file(
    input: 'org.freedesktop.NetworkManager.policy.in',
    output: '@BASENAME@',
    po_dir: po_dir,
    install: true,
    install_dir: polkit_policydir,
  )

  if polkit_noauth_group != ''
    configure_file(
      input: 'org.freedesktop.NetworkManager.rules.in',
      output: '@BASENAME@',
      install_dir: polkit_rulesdir,
      configuration: {'NM_POLKIT_NOAUTH_GROUP': polkit_noauth_group},
    )
  endif
endif

if enable_firewalld_zone
  install_data(
    'nm-shared.xml',
    install_dir: join_paths(nm_prefix, 'lib', 'firewalld', 'zones')
  )
endif
