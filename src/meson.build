# SPDX-License-Identifier: LGPL-2.1-or-later

src_inc = include_directories('.')

###############################################################################

libc_siphash = static_library(
  'c-siphash',
  sources: 'c-siphash/src/c-siphash.c',
  include_directories: include_directories('c-stdaux/src'),
  c_args: '-std=c11',
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
    '-std=c11',
    '-D_GNU_SOURCE',
    '-DSO_ATTACH_BPF=50',
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
    '-std=c11',
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

###############################################################################

subdir('libnm-std-aux')
subdir('libnm-glib-aux')
subdir('libnm-log-null')
subdir('libnm-log-core')
subdir('libnm-systemd-shared')
subdir('libnm-udev-aux')
subdir('libnm-base')
subdir('libnm-platform')
subdir('libnm-core-public')
subdir('libnm-core-intern')
subdir('libnm-core-aux-intern')
subdir('libnm-core-impl')
subdir('libnm-core-aux-extern')
subdir('libnm-client-public')
subdir('libnm-client-impl')
subdir('libnm-client-aux-extern')
subdir('core')
subdir('contrib')

if enable_tests
  subdir('libnm-client-test')
  subdir('libnm-glib-aux/tests')
  subdir('libnm-platform/tests')
  subdir('libnm-core-impl/tests')
  subdir('libnm-client-impl/tests')
  subdir('contrib/tests')
endif
