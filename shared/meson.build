# SPDX-License-Identifier: LGPL-2.1-or-later

shared_inc = include_directories('.')

glib_nm_default_dep = declare_dependency(
  include_directories: [
    shared_inc,
    top_inc,
  ],
  dependencies: [
    glib_dep,
  ],
)

libc_siphash = static_library(
  'c-siphash',
  sources: 'c-siphash/src/c-siphash.c',
  include_directories: include_directories('c-stdaux/src'),
)

libc_rbtree = static_library(
  'c-rbtree',
  sources: 'c-rbtree/src/c-rbtree.c',
  include_directories: include_directories('c-stdaux/src'),
  c_args: '-std=c11',
)

if enable_ebpf
  n_acd_bpf_source = 'n-acd/src/n-acd-bpf.c'
else
  n_acd_bpf_source = 'n-acd/src/n-acd-bpf-fallback.c'
endif

libn_acd = static_library(
  'n-acd',
  sources: files(
    'n-acd/src/n-acd.c',
    'n-acd/src/n-acd-probe.c',
    'n-acd/src/util/timer.c',
    n_acd_bpf_source,
  ),
  include_directories: include_directories(
    'c-list/src',
    'c-rbtree/src',
    'c-siphash/src',
    'c-stdaux/src',
  ),
  c_args: [
    '-D_GNU_SOURCE',
    '-DSO_ATTACH_BPF=50',
    '-std=c11',
    '-Wno-pointer-arith',
    '-Wno-vla',
  ],
  link_with: [
    libc_rbtree,
    libc_siphash,
  ],
)

libn_acd_dep = declare_dependency(
  include_directories: shared_inc,
  link_with: libn_acd,
)

libn_dhcp4 = static_library(
  'n-dhcp4',
  sources: files(
    'n-dhcp4/src/n-dhcp4-c-connection.c',
    'n-dhcp4/src/n-dhcp4-c-lease.c',
    'n-dhcp4/src/n-dhcp4-client.c',
    'n-dhcp4/src/n-dhcp4-c-probe.c',
    'n-dhcp4/src/n-dhcp4-incoming.c',
    'n-dhcp4/src/n-dhcp4-outgoing.c',
    'n-dhcp4/src/n-dhcp4-socket.c',
    'n-dhcp4/src/util/packet.c',
    'n-dhcp4/src/util/socket.c',
  ),
  c_args: [
    '-D_GNU_SOURCE',
    '-Wno-declaration-after-statement',
    '-Wno-pointer-arith',
  ],
  include_directories: include_directories(
    'c-list/src',
    'c-siphash/src',
    'c-stdaux/src',
  ),
  link_with: libc_siphash,
)

libn_dhcp4_dep = declare_dependency(
  include_directories: shared_inc,
  link_with: libn_dhcp4,
)

nm_test_utils_impl_source = files('nm-test-utils-impl.c')

nm_vpn_plugin_utils_source = files('nm-utils/nm-vpn-plugin-utils.c')

libnm_std_aux = static_library(
  'nm-std-aux',
  sources: [
    'nm-std-aux/c-list-util.c',
    'nm-std-aux/nm-std-utils.c',
  ],
  include_directories: top_inc,
)

libnm_glib_aux = static_library(
  'nm-glib-aux',
  sources: files(
    'nm-glib-aux/nm-dbus-aux.c',
    'nm-glib-aux/nm-dedup-multi.c',
    'nm-glib-aux/nm-enum-utils.c',
    'nm-glib-aux/nm-errno.c',
    'nm-glib-aux/nm-hash-utils.c',
    'nm-glib-aux/nm-io-utils.c',
    'nm-glib-aux/nm-json-aux.c',
    'nm-glib-aux/nm-keyfile-aux.c',
    'nm-glib-aux/nm-logging-base.c',
    'nm-glib-aux/nm-random-utils.c',
    'nm-glib-aux/nm-ref-string.c',
    'nm-glib-aux/nm-secret-utils.c',
    'nm-glib-aux/nm-shared-utils.c',
    'nm-glib-aux/nm-time-utils.c',
  ),
  dependencies: glib_nm_default_dep,
  link_with: [
    libc_siphash,
    libnm_std_aux,
  ],
)

libnm_glib_aux_dep = declare_dependency(
  include_directories: [
    shared_inc,
    top_inc,
  ],
  dependencies: [
    glib_nm_default_dep,
  ],
)

libnm_glib_aux_dep_link = declare_dependency(
  dependencies: libnm_glib_aux_dep,
  link_with: libnm_glib_aux,
)

libnm_udev_aux = static_library(
  'nm-udev-aux',
  sources: 'nm-udev-aux/nm-udev-utils.c',
  dependencies: [
    glib_nm_default_dep,
    libudev_dep,
  ],
)

libnm_udev_aux_dep = declare_dependency(
  include_directories: shared_inc,
  link_with: libnm_udev_aux,
)

libnm_base = static_library(
  'nm-base',
  sources: files(
    'nm-base/nm-ethtool-base.c',
  ),
  dependencies: libnm_glib_aux_dep_link,
)

libnm_base_dep = declare_dependency(
  include_directories: shared_inc,
  dependencies: libnm_glib_aux_dep,
)

libnm_base_dep_link = declare_dependency(
  dependencies: libnm_glib_aux_dep_link,
  link_with: libnm_base,
)

libnm_log_core = static_library(
  'nm-log-core',
  sources: 'nm-log-core/nm-logging.c',
  dependencies: [
    glib_nm_default_dep,
    libsystemd_dep,
  ],
)

libnm_log_core_dep = declare_dependency(
  include_directories: shared_inc,
  dependencies: [
    libnm_glib_aux_dep_link,
  ],
  link_with: libnm_log_core,
)

libnm_log_null = static_library(
  'nm-log-null',
  sources: 'nm-log-null/nm-logging-null.c',
  dependencies: glib_nm_default_dep,
)

if enable_tests
  subdir('nm-glib-aux/tests')
endif
