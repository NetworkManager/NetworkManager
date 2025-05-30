# SPDX-License-Identifier: LGPL-2.1-or-later

src_core_inc = include_directories('.')

core_plugin_dep = declare_dependency(
  include_directories: [
    src_core_inc,
    top_inc,
    libnm_core_public_inc,
  ],
  dependencies: [
    libnm_core_public_dep,
    glib_dep,
  ],
)

core_default_dep = declare_dependency(
  include_directories: [
    src_core_inc,
    src_inc,
    top_inc,
  ],
  dependencies: [
    libnm_core_public_dep,
  ],
)

install_data(
  'org.freedesktop.NetworkManager.conf',
  install_dir: dbus_conf_dir,
)

core_plugins = []

libNetworkManagerBase = static_library(
  'NetworkManagerBase',
  sources: files(
    'dhcp/nm-dhcp-client.c',
    'dhcp/nm-dhcp-manager.c',
    'dhcp/nm-dhcp-nettools.c',
    'dhcp/nm-dhcp-systemd.c',
    'dhcp/nm-dhcp-utils.c',
    'dhcp/nm-dhcp-options.c',
    'ndisc/nm-lndp-ndisc.c',
    'ndisc/nm-ndisc.c',
    'main-utils.c',
    'NetworkManagerUtils.c',
    'nm-core-utils.c',
    'nm-dbus-object.c',
    'nm-dbus-utils.c',
    'nm-netns.c',
    'nm-l3-config-data.c',
    'nm-l3-ipv4ll.c',
    'nm-l3-ipv6ll.c',
    'nm-l3cfg.c',
    'nm-bond-manager.c',
    'nm-ip-config.c',
  ),
  dependencies: [
    core_default_dep,
    libnm_core_public_dep,
    libsystemd_dep,
    libudev_dep,
  ],
)

nm_deps = [
  libnm_core_public_dep,
  core_default_dep,
  dl_dep,
  libndp_dep,
  libudev_dep,
  logind_dep,
]

if enable_concheck
  nm_deps += libcurl_dep
endif

if enable_libaudit
  nm_deps += libaudit_dep
endif

if enable_libpsl
  nm_deps += libpsl_dep
endif

if enable_selinux
  nm_deps += selinux_dep
endif

libNetworkManager = static_library(
  'NetworkManager',
  sources: files(
    'devices/nm-device-6lowpan.c',
    'devices/nm-device-bond.c',
    'devices/nm-device-bridge.c',
    'devices/nm-device.c',
    'devices/nm-device-utils.c',
    'devices/nm-device-dummy.c',
    'devices/nm-device-ethernet.c',
    'devices/nm-device-ethernet-utils.c',
    'devices/nm-device-factory.c',
    'devices/nm-device-generic.c',
    'devices/nm-device-hsr.c',
    'devices/nm-device-infiniband.c',
    'devices/nm-device-ip-tunnel.c',
    'devices/nm-device-ipvlan.c',
    'devices/nm-device-loopback.c',
    'devices/nm-device-macsec.c',
    'devices/nm-device-macvlan.c',
    'devices/nm-device-ppp.c',
    'devices/nm-device-tun.c',
    'devices/nm-device-veth.c',
    'devices/nm-device-vlan.c',
    'devices/nm-device-vrf.c',
    'devices/nm-device-vxlan.c',
    'devices/nm-device-wireguard.c',
    'devices/nm-device-wpan.c',
    'devices/nm-lldp-listener.c',
    'dhcp/nm-dhcp-dhclient.c',
    'dhcp/nm-dhcp-dhclient-utils.c',
    'dhcp/nm-dhcp-dhcpcd.c',
    'dhcp/nm-dhcp-listener.c',
    'dns/nm-dns-dnsmasq.c',
    'dns/nm-dns-dnsconfd.c',
    'dns/nm-dns-manager.c',
    'dns/nm-dns-plugin.c',
    'dns/nm-dns-systemd-resolved.c',
    'dnsmasq/nm-dnsmasq-manager.c',
    'dnsmasq/nm-dnsmasq-utils.c',
    'ppp/nm-ppp-manager-call.c',
    'ppp/nm-ppp-mgr.c',
    'settings/plugins/keyfile/nms-keyfile-plugin.c',
    'settings/plugins/keyfile/nms-keyfile-reader.c',
    'settings/plugins/keyfile/nms-keyfile-storage.c',
    'settings/plugins/keyfile/nms-keyfile-utils.c',
    'settings/plugins/keyfile/nms-keyfile-writer.c',
    'settings/nm-agent-manager.c',
    'settings/nm-secret-agent.c',
    'settings/nm-settings.c',
    'settings/nm-settings-connection.c',
    'settings/nm-settings-plugin.c',
    'settings/nm-settings-storage.c',
    'settings/nm-settings-utils.c',
    'supplicant/nm-supplicant-config.c',
    'supplicant/nm-supplicant-interface.c',
    'supplicant/nm-supplicant-manager.c',
    'supplicant/nm-supplicant-settings-verify.c',
    'vpn/nm-vpn-connection.c',
    'vpn/nm-vpn-manager.c',
    'nm-active-connection.c',
    'nm-act-request.c',
    'nm-audit-manager.c',
    'nm-auth-manager.c',
    'nm-auth-utils.c',
    'nm-dbus-manager.c',
    'nm-checkpoint.c',
    'nm-checkpoint-manager.c',
    'nm-config.c',
    'nm-config-data.c',
    'nm-connectivity.c',
    'nm-dcb.c',
    'nm-dhcp-config.c',
    'nm-dispatcher.c',
    'nm-firewall-utils.c',
    'nm-firewalld-manager.c',
    'nm-hostname-manager.c',
    'nm-keep-alive.c',
    'nm-manager.c',
    'nm-pacrunner-manager.c',
    'nm-policy.c',
    'nm-rfkill-manager.c',
    'nm-session-monitor.c',
    'nm-power-monitor.c',
    'nm-priv-helper-call.c',
  ),
  dependencies: nm_deps,
  link_with: [
    libNetworkManagerBase,
    libnm_systemd_core,
    libnm_systemd_shared,
  ],
)

if enable_tests
  test_c_flags = []
  if require_root_tests
    test_c_flags += ['-DREQUIRE_ROOT_TESTS=1']
  endif

  libNetworkManagerTest = static_library(
    'NetworkManagerTest',
    sources: files(
      'ndisc/nm-fake-ndisc.c',
      'platform/tests/test-common.c',
      'platform/nm-fake-platform.c',
    ),
    dependencies: core_default_dep,
    c_args: test_c_flags,
    link_with: libNetworkManager,
  )

  libNetworkManagerTest_dep = declare_dependency(
    dependencies: core_default_dep,
    link_with: [
      libNetworkManagerTest,
      libnm_core_aux_intern,
      libnm_core_impl,
      libnm_crypto,
      libnm_lldp,
      libnm_platform,
      libnm_base,
      libnm_systemd_shared,
      libnm_udev_aux,
      libnm_log_core,
      libnm_glib_aux,
      libnm_std_aux,
      libn_acd,
      libn_dhcp4,
      libc_siphash,
      libc_rbtree,
    ],
  )

  subdir('dnsmasq/tests')
  subdir('ndisc/tests')
  subdir('platform/tests')
  subdir('supplicant/tests')
  subdir('tests')
endif

subdir('dhcp')

if enable_ppp
  subdir('ppp')
endif

subdir('devices')
subdir('settings/plugins')

# NetworkManager binary

# libNetworkManager.a, as built by meson doesn't contain all symbols
# from libNetworkManagerBase.a and other static libraries, unless we
# add dependencies with link_whole, only supported in meson >= 0.46.
# Create an executable with full symbols that we use in place of the
# library to enumerate the symbols.
NetworkManager_all_sym = executable(
  'NetworkManager-all-sym',
  'main.c',
  dependencies: [
    nm_deps,
    libudev_dep,
  ],
  link_args: '-Wl,--no-gc-sections',
  link_whole: [
    libNetworkManager,
    libNetworkManagerBase,
    libnm_core_aux_intern,
    libnm_core_impl,
    libnm_crypto,
    libnm_lldp,
    libnm_platform,
    libnm_base,
    libnm_log_core,
    libnm_udev_aux,
    libnm_glib_aux,
    libnm_std_aux,
    libn_acd,
    libn_dhcp4,
    libc_rbtree,
    libc_siphash,
  ],
)

ver_script = custom_target(
  'NetworkManager.ver',
  output: 'NetworkManager.ver',
  depends: [
    NetworkManager_all_sym,
    core_plugins,
  ],
  command: [
    join_paths(source_root, 'tools', 'create-exports-NetworkManager.sh'),
    '--called-from-build',
    source_root,
  ],
)

NetworkManager = executable(
  'NetworkManager',
  'main.c',
  dependencies: [
    nm_deps,
    libudev_dep,
  ],
  link_with: [
    libNetworkManager,
    libNetworkManagerBase,
    libnm_core_aux_intern,
    libnm_core_impl,
    libnm_crypto,
    libnm_lldp,
    libnm_platform,
    libnm_base,
    libnm_udev_aux,
    libnm_log_core,
    libnm_glib_aux,
    libnm_std_aux,
    libn_acd,
    libn_dhcp4,
    libc_rbtree,
    libc_siphash,
  ],
  link_args: [
    '-rdynamic',
    '-Wl,--version-script,@0@'.format(ver_script.full_path()),
  ],
  link_depends: ver_script,
  install: true,
  install_dir: nm_sbindir,
)

if enable_tests
  foreach plugin: core_plugins
    plugin_path = plugin.full_path()

    test(
      'sym/' + plugin_path.split('/')[-1],
      NetworkManager,
      args: '--version',
      env: ['LD_BIND_NOW=1', 'LD_PRELOAD=' + plugin_path],
    )
  endforeach
endif

test(
  'check-config-options',
  find_program(join_paths(source_root, 'tools', 'check-config-options.sh')),
  args: source_root,
)
