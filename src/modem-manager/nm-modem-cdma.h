/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_MODEM_CDMA_H
#define NM_MODEM_CDMA_H

#include <nm-modem.h>

G_BEGIN_DECLS

#define NM_TYPE_MODEM_CDMA			  (nm_modem_cdma_get_type ())
#define NM_MODEM_CDMA(obj)			  (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_CDMA, NMModemCdma))
#define NM_MODEM_CDMA_CLASS(klass)	  (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_MODEM_CDMA, NMModemCdmaClass))
#define NM_IS_MODEM_CDMA(obj)		  (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_CDMA))
#define NM_IS_MODEM_CDMA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_MODEM_CDMA))
#define NM_MODEM_CDMA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_MODEM_CDMA, NMModemCdmaClass))

typedef struct {
	NMModem parent;
} NMModemCdma;

typedef struct {
	NMModemClass parent;

	/* Signals */
	void (*signal_quality) (NMModemCdma *self, guint32 quality);
} NMModemCdmaClass;

GType nm_modem_cdma_get_type (void);

NMDevice *nm_modem_cdma_new (const char *path,
							 const char *data_device,
							 const char *driver);

G_END_DECLS

#endif /* NM_MODEM_CDMA_H */
