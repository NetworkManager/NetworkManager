// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2009 - 2014 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 * Copyright (C) 2009 Canonical Ltd.
 */

#ifndef __NETWORKMANAGER_MODEM_MANAGER_H__
#define __NETWORKMANAGER_MODEM_MANAGER_H__

#include "nm-modem.h"

#define NM_TYPE_MODEM_MANAGER                   (nm_modem_manager_get_type ())
#define NM_MODEM_MANAGER(obj)                   (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_MANAGER, NMModemManager))
#define NM_MODEM_MANAGER_CLASS(klass)           (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_MODEM_MANAGER, NMModemManagerClass))
#define NM_IS_MODEM_MANAGER(obj)                (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_MANAGER))
#define NM_IS_MODEM_MANAGER_CLASS(klass)        (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_MODEM_MANAGER))
#define NM_MODEM_MANAGER_GET_CLASS(obj)         (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_MODEM_MANAGER, NMModemManagerClass))

#define NM_MODEM_MANAGER_MODEM_ADDED "modem-added"

#define NM_MODEM_MANAGER_NAME_OWNER "name-owner"

#define NM_MODEM_MANAGER_MM_DBUS_SERVICE   "org.freedesktop.ModemManager1"
#define NM_MODEM_MANAGER_MM_DBUS_PATH      "/org/freedesktop/ModemManager1"
#define NM_MODEM_MANAGER_MM_DBUS_INTERFACE "org.freedesktop.ModemManager1"

typedef struct _NMModemManager NMModemManager;
typedef struct _NMModemManagerClass NMModemManagerClass;

GType nm_modem_manager_get_type (void);

NMModemManager *nm_modem_manager_get (void);

void nm_modem_manager_name_owner_ref (NMModemManager *self);
void nm_modem_manager_name_owner_unref (NMModemManager *self);

const char *nm_modem_manager_name_owner_get (NMModemManager *self);

NMModem **nm_modem_manager_get_modems (NMModemManager *self,
                                       guint *out_len);

#endif /* __NETWORKMANAGER_MODEM_MANAGER_H__ */
