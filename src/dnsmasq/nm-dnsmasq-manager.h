// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DNSMASQ_MANAGER_H__
#define __NETWORKMANAGER_DNSMASQ_MANAGER_H__

#include "nm-ip4-config.h"

#define NM_TYPE_DNSMASQ_MANAGER            (nm_dnsmasq_manager_get_type ())
#define NM_DNSMASQ_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManager))
#define NM_DNSMASQ_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManagerClass))
#define NM_IS_DNSMASQ_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNSMASQ_MANAGER))
#define NM_IS_DNSMASQ_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DNSMASQ_MANAGER))
#define NM_DNSMASQ_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManagerClass))

/* signals */
#define NM_DNS_MASQ_MANAGER_STATE_CHANGED "state-changed"

typedef enum {
	NM_DNSMASQ_STATUS_UNKNOWN,
	NM_DNSMASQ_STATUS_DEAD,
	NM_DNSMASQ_STATUS_RUNNING,
} NMDnsMasqStatus;

typedef struct _NMDnsMasqManager NMDnsMasqManager;
typedef struct _NMDnsMasqManagerClass NMDnsMasqManagerClass;

GType nm_dnsmasq_manager_get_type (void);

NMDnsMasqManager *nm_dnsmasq_manager_new (const char *iface);

gboolean nm_dnsmasq_manager_start (NMDnsMasqManager *manager,
                                   NMIP4Config *ip4_config,
                                   gboolean announce_android_metered,
                                   GError **error);

void     nm_dnsmasq_manager_stop  (NMDnsMasqManager *manager);

#endif /* __NETWORKMANAGER_DNSMASQ_MANAGER_H__ */
