/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2009 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_MODEM_GSM_H
#define NM_MODEM_GSM_H

#include <nm-modem.h>

G_BEGIN_DECLS

#define NM_TYPE_MODEM_GSM			 (nm_modem_gsm_get_type ())
#define NM_MODEM_GSM(obj)			 (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_GSM, NMModemGsm))
#define NM_MODEM_GSM_CLASS(klass)	 (G_TYPE_CHECK_CLASS_CAST ((klass),	 NM_TYPE_MODEM_GSM, NMModemGsmClass))
#define NM_IS_MODEM_GSM(obj)		 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_GSM))
#define NM_IS_MODEM_GSM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),	 NM_TYPE_MODEM_GSM))
#define NM_MODEM_GSM_GET_CLASS(obj)	 (G_TYPE_INSTANCE_GET_CLASS ((obj),	 NM_TYPE_MODEM_GSM, NMModemGsmClass))

typedef struct {
	NMModem parent;
} NMModemGsm;

typedef struct {
	NMModemClass parent;

	/* Signals */
	void (*signal_quality) (NMModemGsm *self, guint32 quality);
} NMModemGsmClass;

GType nm_modem_gsm_get_type (void);

NMModem *nm_modem_gsm_new (const char *path,
                           const char *device,
                           const char *data_device,
                           guint32 ip_method);

G_END_DECLS

#endif /* NM_MODEM_GSM_H */
