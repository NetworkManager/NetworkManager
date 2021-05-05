/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2016 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef __NM_FIREWALL_UTILS_H__
#define __NM_FIREWALL_UTILS_H__

typedef struct _NMUtilsShareRules NMUtilsShareRules;

NMUtilsShareRules *nm_utils_share_rules_new(const char *ip_iface, in_addr_t addr, guint8 plen);

void nm_utils_share_rules_free(NMUtilsShareRules *self);

void nm_utils_share_rules_apply(NMUtilsShareRules *self, gboolean shared);

#endif /* __NM_FIREWALL_UTILS_H__ */
