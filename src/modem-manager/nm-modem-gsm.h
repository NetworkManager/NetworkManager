/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

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

NMDevice *nm_modem_gsm_new (const char *path,
							const char *data_device,
							const char *driver);

G_END_DECLS

#endif /* NM_MODEM_GSM_H */
