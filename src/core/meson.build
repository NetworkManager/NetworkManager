# SPDX-License-Identifier: LGPL-2.1-or-later

src_inc = include_directories('.')

core_plugin_dep = declare_dependency(
  sources: libnm_core_enum_sources[1],
  include_directories: [
    src_inc,
    top_inc,
    shared_inc,
    libnm_core_inc,
  ],
  dependencies: [
    glib_dep,
  ],
)

core_default_dep = declare_dependency(
  sources: libnm_core_enum_sources[1],
  include_directories: src_inc,
  dependencies: [
    libnm_core_nm_default_dep,
    libnm_log_core_dep,
    libnm_platform_dep,
  ],
)

install_data(
  'org.freedesktop.NetworkManager.conf',
  install_dir: dbus_conf_dir,
)

subdir('systemd')

core_plugins = []

daemon_c_flags = [
  '-DG_LOG_DOMAIN="NetworkManager"',
]

platform_wifi_wext_source = files()
if enable_wext
  platform_wifi_wext_source += files('platform/wifi/nm-wifi-utils-wext.c')
endif

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
    'platform/wifi/nm-wifi-utils-nl80211.c',
    'platform/wifi/nm-wifi-utils.c',
    'platform/wpan/nm-wpan-utils.c',
    'platform/nm-linux-platform.c',
    'platform/nm-platform.c',
    'platform/nmp-object.c',
    'platform/nmp-rules-manager.c',
    'main-utils.c',
    'NetworkManagerUtils.c',
    'nm-core-utils.c',
    'nm-dbus-object.c',
    'nm-dbus-utils.c',
    'nm-netns.c',
    'nm-l3-config-data.c',
    'nm-l3-ipv4ll.c',
    'nm-l3cfg.c',
    'nm-ip-config.c',
    'nm-ip4-config.c',
    'nm-ip6-config.c',
  ) + platform_wifi_wext_source,
  dependencies: [
    core_default_dep,
    libn_dhcp4_dep,
    libnm_keyfile_dep,
    libnm_core_dep,
    libnm_systemd_shared_dep,
    libnm_udev_aux_dep,
    libsystemd_dep,
    libudev_dep,
  ],
  c_args: daemon_c_flags,
)

nm_deps = [
  core_default_dep,
  dl_dep,
  libn_acd_dep,
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
    'devices/nm-acd-manager.c',
    'devices/nm-device-6lowpan.c',
    'devices/nm-device-bond.c',
    'devices/nm-device-bridge.c',
    'devices/nm-device.c',
    'devices/nm-device-dummy.c',
    'devices/nm-device-ethernet.c',
    'devices/nm-device-ethernet-utils.c',
    'devices/nm-device-factory.c',
    'devices/nm-device-generic.c',
    'devices/nm-device-infiniband.c',
    'devices/nm-device-ip-tunnel.c',
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
    'dhcp/nm-dhcp-dhcpcanon.c',
    'dhcp/nm-dhcp-dhcpcd.c',
    'dhcp/nm-dhcp-listener.c',
    'dns/nm-dns-dnsmasq.c',
    'dns/nm-dns-manager.c',
    'dns/nm-dns-plugin.c',
    'dns/nm-dns-systemd-resolved.c',
    'dns/nm-dns-unbound.c',
    'dnsmasq/nm-dnsmasq-manager.c',
    'dnsmasq/nm-dnsmasq-utils.c',
    'ppp/nm-ppp-manager-call.c',
    'settings/plugins/keyfile/nms-keyfile-storage.c',
    'settings/plugins/keyfile/nms-keyfile-plugin.c',
    'settings/plugins/keyfile/nms-keyfile-reader.c',
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
    'nm-firewall-manager.c',
    'nm-hostname-manager.c',
    'nm-keep-alive.c',
    'nm-manager.c',
    'nm-pacrunner-manager.c',
    'nm-policy.c',
    'nm-proxy-config.c',
    'nm-rfkill-manager.c',
    'nm-session-monitor.c',
    'nm-sleep-monitor.c',
  ),
  dependencies: nm_deps,
  c_args: daemon_c_flags,
  link_with: [
    libNetworkManagerBase,
    libnm_systemd_core,
    libnm_systemd_shared,
  ],
)

executable(
  'nm-iface-helper',
  'nm-iface-helper.c',
  dependencies: [
    core_default_dep,
    dl_dep,
    libndp_dep,
    libudev_dep,
    libn_acd_dep,
  ],
  c_args: daemon_c_flags,
  link_with: [
    libNetworkManagerBase,
    libnm_systemd_core,
    libnm_systemd_shared,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  test_c_flags = daemon_c_flags
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
    link_with: libNetworkManagerTest,
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
subdir('initrd')
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
  dependencies: nm_deps,
  c_args: daemon_c_flags,
  link_args: '-Wl,--no-gc-sections',
  link_whole: [
    libNetworkManager,
    libNetworkManagerBase,
    libnm_core,
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
  dependencies: nm_deps,
  c_args: daemon_c_flags,
  link_with: libNetworkManager,
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
