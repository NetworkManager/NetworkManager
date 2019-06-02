/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2016 Red Hat, Inc.
 */

#ifndef __NM_DNS_MANAGER_H__
#define __NM_DNS_MANAGER_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-object.h"
#include "nm-client.h"

#define NM_TYPE_DNS_MANAGER            (nm_dns_manager_get_type ())
#define NM_DNS_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNS_MANAGER, NMDnsManager))
#define NM_DNS_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))
#define NM_IS_DNS_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNS_MANAGER))
#define NM_IS_DNS_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DNS_MANAGER))
#define NM_DNS_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNS_MANAGER, NMDnsManagerClass))

#define NM_DNS_MANAGER_MODE            "mode"
#define NM_DNS_MANAGER_RC_MANAGER      "rc-manager"
#define NM_DNS_MANAGER_CONFIGURATION   "configuration"

typedef struct _NMDnsManager NMDnsManager;
typedef struct _NMDnsManagerClass NMDnsManagerClass;

/**
 * NMDnsManager:
 */
struct _NMDnsManager {
	NMObject parent;
};

struct _NMDnsManagerClass {
	NMObjectClass parent;
};

GType nm_dns_manager_get_type (void);

const char *nm_dns_manager_get_mode   (NMDnsManager *manager);
const char *nm_dns_manager_get_rc_manager (NMDnsManager *manager);
const GPtrArray *nm_dns_manager_get_configuration (NMDnsManager *manager);

NMDnsEntry *       nm_dns_entry_new (const char *interface,
                                     const char * const *nameservers,
                                     const char * const *domains,
                                     int priority,
                                     gboolean vpn);
NMDnsEntry *        nm_dns_entry_dup (NMDnsEntry *entry);

#endif /* __NM_DNS_MANAGER_H__ */
