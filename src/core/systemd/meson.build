# SPDX-License-Identifier: LGPL-2.1-or-later

incs = include_directories(
  'sd-adapt-core',
  'src/libsystemd-network',
  'src/libsystemd/sd-event',
  'src/systemd',
)

libnm_systemd_core = static_library(
  'nm-systemd-core',
  sources: files(
    'src/libsystemd-network/arp-util.c',
    'src/libsystemd-network/dhcp-identifier.c',
    'src/libsystemd-network/dhcp-network.c',
    'src/libsystemd-network/dhcp-option.c',
    'src/libsystemd-network/dhcp-packet.c',
    'src/libsystemd-network/dhcp6-network.c',
    'src/libsystemd-network/dhcp6-option.c',
    'src/libsystemd-network/lldp-neighbor.c',
    'src/libsystemd-network/lldp-network.c',
    'src/libsystemd-network/network-internal.c',
    'src/libsystemd-network/sd-dhcp-client.c',
    'src/libsystemd-network/sd-dhcp-lease.c',
    'src/libsystemd-network/sd-dhcp6-client.c',
    'src/libsystemd-network/sd-dhcp6-lease.c',
    'src/libsystemd-network/sd-ipv4acd.c',
    'src/libsystemd-network/sd-ipv4ll.c',
    'src/libsystemd-network/sd-lldp.c',
    'src/libsystemd/sd-event/event-util.c',
    'src/libsystemd/sd-event/sd-event.c',
    'src/libsystemd/sd-id128/id128-util.c',
    'src/libsystemd/sd-id128/sd-id128.c',
    'nm-sd.c',
    'nm-sd-utils-core.c',
    'nm-sd-utils-dhcp.c',
    'sd-adapt-core/nm-sd-adapt-core.c',
  ),
  include_directories: [
    incs,
    src_inc,
  ],
  dependencies: [
    glib_nm_default_dep,
    libnm_core_dep,
    libnm_systemd_shared_dep,
  ],
  c_args: [
    '-DG_LOG_DOMAIN="NetworkManager"',
  ],
  link_with: libc_siphash,
)

libnm_systemd_core_dep = declare_dependency(
  include_directories: incs,
  dependencies: [
    glib_dep,
    libnm_core_dep,
    libnm_systemd_shared_dep,
  ],
  link_with: libnm_systemd_core,
)
