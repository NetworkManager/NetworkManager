// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_FIREWALL_MANAGER_H__
#define __NETWORKMANAGER_FIREWALL_MANAGER_H__

#define NM_TYPE_FIREWALL_MANAGER                (nm_firewall_manager_get_type ())
#define NM_FIREWALL_MANAGER(obj)                (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_FIREWALL_MANAGER, NMFirewallManager))
#define NM_FIREWALL_MANAGER_CLASS(klass)        (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_FIREWALL_MANAGER, NMFirewallManagerClass))
#define NM_IS_FIREWALL_MANAGER(obj)             (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_FIREWALL_MANAGER))
#define NM_IS_FIREWALL_MANAGER_CLASS(klass)     (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_FIREWALL_MANAGER))
#define NM_FIREWALL_MANAGER_GET_CLASS(obj)      (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_FIREWALL_MANAGER, NMFirewallManagerClass))

#define NM_FIREWALL_MANAGER_STATE_CHANGED "state-changed"

typedef struct _NMFirewallManagerCallId NMFirewallManagerCallId;

typedef struct _NMFirewallManager NMFirewallManager;
typedef struct _NMFirewallManagerClass NMFirewallManagerClass;

GType nm_firewall_manager_get_type (void);

NMFirewallManager *nm_firewall_manager_get (void);

gboolean nm_firewall_manager_get_running (NMFirewallManager *self);

typedef void (*NMFirewallManagerAddRemoveCallback) (NMFirewallManager *self,
                                                    NMFirewallManagerCallId *call_id,
                                                    GError *error,
                                                    gpointer user_data);

NMFirewallManagerCallId *nm_firewall_manager_add_or_change_zone (NMFirewallManager *mgr,
                                                                 const char *iface,
                                                                 const char *zone,
                                                                 gboolean add,
                                                                 NMFirewallManagerAddRemoveCallback callback,
                                                                 gpointer user_data);
NMFirewallManagerCallId *nm_firewall_manager_remove_from_zone (NMFirewallManager *mgr,
                                                               const char *iface,
                                                               const char *zone,
                                                               NMFirewallManagerAddRemoveCallback callback,
                                                               gpointer user_data);

void nm_firewall_manager_cancel_call (NMFirewallManagerCallId *call_id);

#endif /* __NETWORKMANAGER_FIREWALL_MANAGER_H__ */
