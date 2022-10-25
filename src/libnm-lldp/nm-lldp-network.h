/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef __NM_LLDP_NETWORK_H__
#define __NM_LLDP_NETWORK_H__

#define NM_ETHERTYPE_LLDP 0x88cc

int nm_lldp_network_bind_raw_socket(int ifindex);

#endif /* __NM_LLDP_NETWORK_H__ */
