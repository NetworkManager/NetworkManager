/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
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
