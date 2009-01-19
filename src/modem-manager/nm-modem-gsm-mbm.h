/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
  Additions to NetworkManager, network-manager-applet and modemmanager
  for supporting Ericsson modules like F3507g.

  Author: Per Hallsmark <per@hallsmark.se>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the

  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifndef NM_MODEM_GSM_MBM_H
#define NM_MODEM_GSM_MBM_H

#include <nm-modem-gsm.h>

G_BEGIN_DECLS

#define NM_TYPE_MODEM_GSM_MBM			 (nm_modem_gsm_mbm_get_type ())
#define NM_MODEM_GSM_MBM(obj)			 (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_GSM_MBM, NMModemGsmMbm))
#define NM_MODEM_GSM_MBM_CLASS(klass)	 (G_TYPE_CHECK_CLASS_CAST ((klass),	 NM_TYPE_MODEM_GSM_MBM, NMModemGsmMbmClass))
#define NM_IS_MODEM_GSM_MBM(obj)		 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_GSM_MBM))
#define NM_IS_MODEM_GSM_MBM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),	 NM_TYPE_MODEM_GSM_MBM))
#define NM_MODEM_GSM_MBM_GET_CLASS(obj)	 (G_TYPE_INSTANCE_GET_CLASS ((obj),	 NM_TYPE_MODEM_GSM_MBM, NMModemGsmMbmClass))

typedef struct {
	NMModemGsm parent;
} NMModemGsmMbm;

typedef struct {
	NMModemGsmClass parent;
} NMModemGsmMbmClass;

GType nm_modem_gsm_mbm_get_type (void);

NMDevice *nm_modem_gsm_mbm_new (const char *path,
								const char *data_device,
								const char *driver);

G_END_DECLS

#endif /* NM_MODEM_GSM_MBM_H */
