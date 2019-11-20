// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2012 - Aleksander Morgado <aleksander@gnu.org>
 */

#ifndef __NETWORKMANAGER_MODEM_BROADBAND_H__
#define __NETWORKMANAGER_MODEM_BROADBAND_H__

#include "nm-modem.h"

#define NM_TYPE_MODEM_BROADBAND            (nm_modem_broadband_get_type ())
#define NM_MODEM_BROADBAND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_BROADBAND, NMModemBroadband))
#define NM_MODEM_BROADBAND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_MODEM_BROADBAND, NMModemBroadbandClass))
#define NM_IS_MODEM_BROADBAND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_BROADBAND))
#define NM_IS_MODEM_BROADBAND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_MODEM_BROADBAND))
#define NM_MODEM_BROADBAND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_MODEM_BROADBAND, NMModemBroadbandClass))

typedef struct _NMModemBroadband NMModemBroadband;
typedef struct _NMModemBroadbandClass NMModemBroadbandClass;

GType nm_modem_broadband_get_type (void);

NMModem *nm_modem_broadband_new (GObject *object, GError **error);

#endif /* __NETWORKMANAGER_MODEM_BROADBAND_H__ */
