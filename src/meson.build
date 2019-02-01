src_inc = include_directories('.')

install_data(
  'org.freedesktop.NetworkManager.conf',
  install_dir: dbus_conf_dir,
)

subdir('systemd')

core_plugins = []

nm_cflags = ['-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DAEMON']

nm_dep = declare_dependency(
  include_directories: src_inc,
  dependencies: nm_core_dep,
  compile_args: nm_cflags,
)

cflags = nm_cflags

sources = files(
  'dhcp/nm-dhcp-client.c',
  'dhcp/nm-dhcp-manager.c',
  'dhcp/nm-dhcp-systemd.c',
  'dhcp/nm-dhcp-utils.c',
  'ndisc/nm-lndp-ndisc.c',
  'ndisc/nm-ndisc.c',
  'platform/nm-netlink.c',
  'platform/wifi/nm-wifi-utils-nl80211.c',
  'platform/wifi/nm-wifi-utils.c',
  'platform/wpan/nm-wpan-utils.c',
  'platform/nm-linux-platform.c',
  'platform/nm-platform.c',
  'platform/nm-platform-utils.c',
  'platform/nmp-netns.c',
  'platform/nmp-object.c',
  'main-utils.c',
  'NetworkManagerUtils.c',
  'nm-core-utils.c',
  'nm-dbus-object.c',
  'nm-dbus-utils.c',
  'nm-ip4-config.c',
  'nm-ip6-config.c',
  'nm-logging.c',
)

deps = [
  libsystemd_dep,
  libudev_dep,
  nm_core_dep,
]

if enable_wext
  sources += files('platform/wifi/nm-wifi-utils-wext.c')
endif

libnetwork_manager_base = static_library(
  nm_name + 'Base',
  sources: sources,
  dependencies: deps,
  c_args: cflags,
  link_with: libnm_core,
)

sources = files(
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
  'settings/plugins/keyfile/nms-keyfile-connection.c',
  'settings/plugins/keyfile/nms-keyfile-plugin.c',
  'settings/plugins/keyfile/nms-keyfile-reader.c',
  'settings/plugins/keyfile/nms-keyfile-utils.c',
  'settings/plugins/keyfile/nms-keyfile-writer.c',
  'settings/nm-agent-manager.c',
  'settings/nm-secret-agent.c',
  'settings/nm-settings.c',
  'settings/nm-settings-connection.c',
  'settings/nm-settings-plugin.c',
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
  'nm-auth-subject.c',
  'nm-auth-utils.c',
  'nm-dbus-manager.c',
  'nm-checkpoint.c',
  'nm-checkpoint-manager.c',
  'nm-config.c',
  'nm-config-data.c',
  'nm-connectivity.c',
  'nm-dcb.c',
  'nm-dhcp4-config.c',
  'nm-dhcp6-config.c',
  'nm-dispatcher.c',
  'nm-firewall-manager.c',
  'nm-hostname-manager.c',
  'nm-keep-alive.c',
  'nm-manager.c',
  'nm-netns.c',
  'nm-pacrunner-manager.c',
  'nm-policy.c',
  'nm-proxy-config.c',
  'nm-rfkill-manager.c',
  'nm-session-monitor.c',
  'nm-sleep-monitor.c',
)

nm_deps = [
  dl_dep,
  libndp_dep,
  libudev_dep,
  nm_core_dep,
  shared_n_acd_dep,
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

libnetwork_manager = static_library(
  nm_name,
  sources: sources,
  dependencies: nm_deps,
  c_args: cflags,
  link_with: [
    libnetwork_manager_base,
    libnm_systemd_core,
    libnm_systemd_shared,
  ],
)

deps = [
  dl_dep,
  libndp_dep,
  libudev_dep,
  nm_core_dep,
]

name = 'nm-iface-helper'

executable(
  name,
  name + '.c',
  dependencies: deps,
  c_args: cflags,
  link_with: [
    libnetwork_manager_base,
    libnm_systemd_core,
    libnm_systemd_shared,
  ],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir,
)

if enable_tests
  sources = files(
    'ndisc/nm-fake-ndisc.c',
    'platform/tests/test-common.c',
    'platform/nm-fake-platform.c',
  )

  deps = [
    libudev_dep,
    nm_core_dep,
  ]

  test_cflags = ['-DNETWORKMANAGER_COMPILATION_TEST']
  if require_root_tests
    test_cflags += ['-DREQUIRE_ROOT_TESTS=1']
  endif

  libnetwork_manager_test = static_library(
    nm_name + 'Test',
    sources: sources,
    dependencies: deps,
    c_args: cflags + test_cflags,
    link_with: libnetwork_manager,
  )

  test_nm_dep = declare_dependency(
    dependencies: nm_dep,
    compile_args: test_cflags,
    link_with: libnetwork_manager_test,
  )

  test_nm_dep_fake = declare_dependency(
    dependencies: test_nm_dep,
    compile_args: ['-DSETUP=nm_fake_platform_setup']
  )

  test_nm_dep_linux = declare_dependency(
    dependencies: test_nm_dep,
    compile_args: ['-DSETUP=nm_linux_platform_setup']
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

create_exports_networkmanager = join_paths(meson.source_root(), 'tools', 'create-exports-NetworkManager.sh')
symbol_map_name = 'NetworkManager.ver'

# libNetworkManager.a, as built by meson doesn't contain all symbols
# from libNetworkManagerBase.a and other static libraries, unless we
# add dependencies with link_whole, only supported in meson >= 0.46.
# Create an executable with full symbols that we use in place of the
# library to enumerate the symbols.
network_manager_sym = executable(
  'nm-full-symbols',
  'main.c',
  c_args: nm_cflags,
  link_args: '-Wl,--no-gc-sections',
  dependencies: nm_deps,
  link_whole: [libnetwork_manager, libnetwork_manager_base, libnm_core],
  install: false,
)

# this uses symbols from nm-full-symbols instead of libNetworkManager.a
ver_script = custom_target(
  symbol_map_name,
  input: meson.source_root(),
  output: symbol_map_name,
  depends: [ network_manager_sym, core_plugins ],
  command: [create_exports_networkmanager, '--called-from-build', '@INPUT@'],
)

ldflags = ['-rdynamic', '-Wl,--version-script,@0@'.format(ver_script.full_path())]

network_manager = executable(
  nm_name,
  'main.c',
  dependencies: nm_deps,
  c_args: nm_cflags,
  link_with: libnetwork_manager,
  link_args: ldflags,
  link_depends: ver_script,
  install: true,
  install_dir: nm_sbindir,
)

if enable_tests
  foreach plugin : core_plugins
    test ('sym/' + plugin.full_path().split('/')[-1],
          network_manager,
          args: '--version',
          env: ['LD_BIND_NOW=1', 'LD_PRELOAD=' + plugin.full_path()])
  endforeach
endif

test(
  'check-config-options',
  find_program(join_paths(meson.source_root(), 'tools', 'check-config-options.sh')),
  args: [meson.source_root()]
)
