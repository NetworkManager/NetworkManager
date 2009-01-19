/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_MODEM_GSM_HSO_H
#define NM_MODEM_GSM_HSO_H

#include <nm-modem-gsm.h>

G_BEGIN_DECLS

#define NM_TYPE_MODEM_GSM_HSO			 (nm_modem_gsm_hso_get_type ())
#define NM_MODEM_GSM_HSO(obj)			 (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_GSM_HSO, NMModemGsmHso))
#define NM_MODEM_GSM_HSO_CLASS(klass)	 (G_TYPE_CHECK_CLASS_CAST ((klass),	 NM_TYPE_MODEM_GSM_HSO, NMModemGsmHsoClass))
#define NM_IS_MODEM_GSM_HSO(obj)		 (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_GSM_HSO))
#define NM_IS_MODEM_GSM_HSO_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),	 NM_TYPE_MODEM_GSM_HSO))
#define NM_MODEM_GSM_HSO_GET_CLASS(obj)	 (G_TYPE_INSTANCE_GET_CLASS ((obj),	 NM_TYPE_MODEM_GSM_HSO, NMModemGsmHsoClass))

typedef struct {
	NMModemGsm parent;
} NMModemGsmHso;

typedef struct {
	NMModemGsmClass parent;
} NMModemGsmHsoClass;

GType nm_modem_gsm_hso_get_type (void);

NMDevice *nm_modem_gsm_hso_new (const char *path,
								const char *data_device,
								const char *driver);

G_END_DECLS

#endif /* NM_MODEM_GSM_HSO_H */
