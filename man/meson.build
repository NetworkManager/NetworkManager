common_conf = configuration_data()
common_conf.set('NM_VERSION', nm_version)
common_conf.set('sysconfdir', nm_sysconfdir)
common_conf.set('nmrundir', nm_pkgrundir)
common_conf.set('nmstatedir', nm_pkgstatedir)
common_conf.set('NM_CONFIG_DEFAULT_MAIN_AUTH_POLKIT_TEXT', config_default_main_auth_polkit)
common_conf.set('NM_CONFIG_DEFAULT_LOGGING_BACKEND_TEXT', config_logging_backend_default)
common_conf.set('NM_CONFIG_DEFAULT_LOGGING_AUDIT_TEXT', config_default_logging_audit)
common_conf.set('NM_CONFIG_DEFAULT_MAIN_RC_MANAGER', config_dns_rc_manager_default)
common_conf.set('NM_CONFIG_DEFAULT_MAIN_DHCP', config_dhcp_default)

common = 'common.ent'

common_ent_file = configure_file(
  input: common + '.in',
  output: common,
  configuration: common_conf,
)

xsltproc_options = [
  xsltproc,
  '--output', '@OUTPUT@',
  '--path', meson.current_build_dir(),
  '--xinclude',
  '--nonet',
  '--stringparam', 'man.output.quietly', '1',
  '--stringparam', 'funcsynopsis.style', 'ansi',
  '--stringparam', 'man.th.extra1.suppress', '1',
  '--stringparam', 'man.authors.section.enabled', '0',
  '--stringparam', 'man.copyright.section.enabled', '0',
  '--stringparam', 'man.th.title.max.length', '30',
]

docbook_xls = 'http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl'

mans_xmls = []

mans = [
  ['NetworkManager', '8'],
  ['NetworkManager.conf', '5'],
  ['nm-online', '1'],
  ['nmcli-examples', '7'],
  ['nmcli', '1'],
  ['nmtui', '1'],
  ['nm-initrd-generator', '8'],
]

if enable_ovs
  mans += [['nm-openvswitch', '7']]
endif

foreach man: mans
  input = man[0] + '.xml'
  content_files += join_paths(meson.current_source_dir(), input)

  output = '@0@.@1@'.format(man[0], man[1])

  custom_target(
    output,
    input: input,
    output: output,
    command: xsltproc_options + [docbook_xls, '@INPUT@'],
    depend_files: common_ent_file,
    install: true,
    install_dir: join_paths(nm_mandir, 'man' + man[1]),
  )
endforeach

if enable_introspection
  mans = [
    ['nm-settings-keyfile', '5', nm_settings_keyfile_docs],
    ['nm-settings', '5', nm_settings_docs],
  ]

  if enable_ifcfg_rh
    mans += [['nm-settings-ifcfg-rh', '5', nm_settings_ifcfg_rh_docs]]
  endif

  foreach man: mans
    output = man[0] + '.xml'

    input = custom_target(
      output,
      input: man[2],
      output: output,
      command: xsltproc_options + [join_paths(meson.current_source_dir(), man[0] + '.xsl'), '@INPUT@'],
    )
    content_files += input.full_path()

    output = '@0@.@1@'.format(man[0], man[1])

    custom_target(
      output,
      input: input,
      output: output,
      command: xsltproc_options + [docbook_xls, '@INPUT@'],
      install: true,
      install_dir: join_paths(nm_mandir, 'man' + man[1]),
    )
  endforeach
endif
