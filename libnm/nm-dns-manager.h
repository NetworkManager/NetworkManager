/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2016 Red Hat, Inc.
 */

#ifndef __NM_DNS_MANAGER_H__
#define __NM_DNS_MANAGER_H__

#if !((NETWORKMANAGER_COMPILATION) &NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
    #error Cannot use this header.
#endif

#include "nm-client.h"

NMDnsEntry *nm_dns_entry_new(const char *       interface,
                             const char *const *nameservers,
                             const char *const *domains,
                             int                priority,
                             gboolean           vpn);
NMDnsEntry *nm_dns_entry_dup(NMDnsEntry *entry);

#endif /* __NM_DNS_MANAGER_H__ */
