src_inc = include_directories('.')

install_data(
  'org.freedesktop.NetworkManager.conf',
  install_dir: dbus_conf_dir
)

subdir('systemd')

core_plugins = []

nm_cflags = ['-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_DAEMON']

nm_dep = declare_dependency(
  include_directories: src_inc,
  dependencies: nm_core_dep,
  compile_args: nm_cflags
)

cflags = nm_cflags + [
  '-DPREFIX="@0@"'.format(nm_prefix),
  '-DBINDIR="@0@"'.format(nm_bindir),
  '-DDATADIR="@0@"'.format(nm_datadir),
  '-DLIBEXECDIR="@0@"'.format(nm_libexecdir),
  '-DLOCALSTATEDIR="@0@"'.format(nm_localstatedir),
  '-DRUNSTATEDIR="@0@"'.format(nm_runstatedir),
  '-DSBINDIR="@0@"'.format(nm_sbindir),
  '-DSYSCONFDIR="@0@"'.format(nm_sysconfdir),
  '-DRUNDIR="@0@"'.format(nm_pkgrundir),
  '-DNMCONFDIR="@0@"'.format(nm_pkgconfdir),
  '-DNMLOCALEDIR="@0@"'.format(nm_localedir),
  '-DNMPLUGINDIR="@0@"'.format(nm_plugindir),
  '-DNMRUNDIR="@0@"'.format(nm_pkgrundir),
  '-DNMSTATEDIR="@0@"'.format(nm_pkgstatedir),
  '-DNMLIBDIR="@0@"'.format(nm_pkglibdir)
]

if enable_dhcpcanon
  cflags += '-DDHCPCANON_PATH="@0@"'.format(dhcpcanon.path())
endif

if enable_dhclient
  cflags += '-DDHCLIENT_PATH="@0@"'.format(dhclient.path())
endif

if enable_dhcpcd
  cflags += '-DDHCPCD_PATH="@0@"'.format(dhcpcd.path())
endif

sources = files(
  'dhcp/nm-dhcp-client.c',
  'dhcp/nm-dhcp-manager.c',
  'dhcp/nm-dhcp-systemd.c',
  'dhcp/nm-dhcp-utils.c',
  'ndisc/nm-lndp-ndisc.c',
  'ndisc/nm-ndisc.c',
  'platform/nm-netlink.c',
  'platform/wifi/wifi-utils-nl80211.c',
  'platform/wifi/wifi-utils.c',
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
  'nm-logging.c'
)

deps = [
  libsystemd_dep,
  libudev_dep,
  nm_core_dep
]

if enable_wext
  sources += files('platform/wifi/wifi-utils-wext.c')
endif

libnetwork_manager_base = static_library(
  nm_name + 'Base',
  sources: sources,
  dependencies: deps,
  c_args: cflags,
  link_with: libnm_core
)

sources = files(
  'devices/nm-acd-manager.c',
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
  'nm-manager.c',
  'nm-netns.c',
  'nm-pacrunner-manager.c',
  'nm-policy.c',
  'nm-proxy-config.c',
  'nm-rfkill-manager.c',
  'nm-session-monitor.c',
  'nm-sleep-monitor.c'
)

deps = [
  dl_dep,
  libndp_dep,
  # FIXME: Some files use introspection/dbus* headers, so
  #        this dependency might be needed
  #libnmdbus_dep,
  libudev_dep,
  nm_core_dep,
  shared_n_acd_dep
]

if enable_concheck
  deps += libcurl_dep
endif

if enable_libaudit
  deps += libaudit_dep
endif

if enable_libpsl
  deps += libpsl_dep
endif

if enable_selinux
  deps += selinux_dep
endif

if enable_session_tracking
  deps += logind_dep
endif

libnetwork_manager = static_library(
  nm_name,
  sources: sources,
  dependencies: deps,
  c_args: cflags,
  link_with: [libnetwork_manager_base, libsystemd_nm]
)

ldflags = ['-rdynamic']

# FIXME: this doesn't work and it depends on libtool
'''
src/NetworkManager.ver: src/libNetworkManager.la $(core_plugins)
  $(AM_V_GEN) NM="$(NM)" "$(srcdir)/tools/create-exports-NetworkManager.sh" --called-from-make "$(srcdir)"

src_NetworkManager_LDFLAGS = \
  -rdynamic \
  -Wl,--version-script="src/NetworkManager.ver"

nm = find_program('gcc-nm', 'nm')
create_exports_networkmanager = join_paths(meson.source_root(), 'tools', 'create-exports-NetworkManager.sh')

symbol_map_name = 'NetworkManager.ver'

linker_script = custom_target(
  symbol_map_name,
  input: meson.source_root(),
  output: symbol_map_name,
  capture: true,
  #command: ['NM=' + nm.path(), create_exports_networkmanager, '--called-from-make', '@INPUT@']
  command: [create_exports_networkmanager, '--called-from-make', '@INPUT@']
)

ldflags += '-Wl,--version-script,@0@'.format(linker_script)
'''

network_manager = executable(
  nm_name,
  'main.c',
  dependencies: deps,
  c_args: cflags,
  link_with: libnetwork_manager,
  link_args: ldflags,
  #FIXME
  #link_depends: linker_script,
  install: true,
  install_dir: nm_sbindir
)

deps = [
  dl_dep,
  libndp_dep,
  libudev_dep,
  nm_core_dep
]

name = 'nm-iface-helper'

executable(
  name,
  name + '.c',
  dependencies: deps,
  c_args: cflags,
  link_with: [libnetwork_manager_base, libsystemd_nm],
  link_args: ldflags_linker_script_binary,
  link_depends: linker_script_binary,
  install: true,
  install_dir: nm_libexecdir
)

if enable_tests
  sources = files(
    'ndisc/nm-fake-ndisc.c',
    'platform/tests/test-common.c',
    'platform/nm-fake-platform.c'
  )

  deps = [
    libudev_dep,
    nm_core_dep
  ]

  test_cflags = ['-DNETWORKMANAGER_COMPILATION_TEST']
  if require_root_tests
    test_cflags += ['-DREQUIRE_ROOT_TESTS=1']
  endif

  platform = (host_machine.system().contains('linux') ? 'linux' : 'fake')
  test_cflags_platform = '-DSETUP=nm_' + platform + '_platform_setup'

  libnetwork_manager_test = static_library(
    nm_name + 'Test',
    sources: sources,
    dependencies: deps,
    c_args: cflags + test_cflags,
    link_with: libnetwork_manager
  )

  test_nm_dep = declare_dependency(
    dependencies: nm_dep,
    compile_args: test_cflags,
    link_with: libnetwork_manager_test
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
