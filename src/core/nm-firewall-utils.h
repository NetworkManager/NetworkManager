/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2016 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef __NM_FIREWALL_UTILS_H__
#define __NM_FIREWALL_UTILS_H__

typedef enum {
    NM_FIREWALL_BACKEND_UNKNOWN,
    NM_FIREWALL_BACKEND_NONE,
    NM_FIREWALL_BACKEND_IPTABLES,
    NM_FIREWALL_BACKEND_NFTABLES,
} NMFirewallBackend;

NMFirewallBackend nm_firewall_utils_get_backend(void);

/*****************************************************************************/

typedef struct _NMFirewallConfig NMFirewallConfig;

NMFirewallConfig *nm_firewall_config_new_shared(const char *ip_iface, in_addr_t addr, guint8 plen);

void nm_firewall_config_free(NMFirewallConfig *self);

void nm_firewall_config_apply_sync(NMFirewallConfig *self, gboolean up);

/*****************************************************************************/

void nm_firewall_nft_call(GBytes             *stdin_buf,
                          GCancellable       *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer            callback_user_data);

gboolean nm_firewall_nft_call_finish(GAsyncResult *result, GError **error);

GBytes *nm_firewall_nft_stdio_mlag(gboolean           up,
                                   const char        *bond_ifname,
                                   const char *const *bond_ifnames_down,
                                   const char *const *active_members,
                                   const char *const *previous_members);

#endif /* __NM_FIREWALL_UTILS_H__ */
