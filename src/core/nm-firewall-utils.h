/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2016 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef __NM_FIREWALL_UTILS_H__
#define __NM_FIREWALL_UTILS_H__

typedef struct _NMFirewallConfig NMFirewallConfig;

NMFirewallConfig *nm_firewall_config_new(const char *ip_iface, in_addr_t addr, guint8 plen);

void nm_firewall_config_free(NMFirewallConfig *self);

void nm_firewall_config_apply(NMFirewallConfig *self, gboolean shared);

#endif /* __NM_FIREWALL_UTILS_H__ */
