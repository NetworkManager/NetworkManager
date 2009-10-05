/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_MODEM_MANAGER_H
#define NM_MODEM_MANAGER_H

#include <glib-object.h>
#include "nm-modem.h"

#define NM_TYPE_MODEM_MANAGER				(nm_modem_manager_get_type ())
#define NM_MODEM_MANAGER(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MODEM_MANAGER, NMModemManager))
#define NM_MODEM_MANAGER_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),	NM_TYPE_MODEM_MANAGER, NMModemManagerClass))
#define NM_IS_MODEM_MANAGER(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MODEM_MANAGER))
#define NM_IS_MODEM_MANAGER_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),	NM_TYPE_MODEM_MANAGER))
#define NM_MODEM_MANAGER_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),	NM_TYPE_MODEM_MANAGER, NMModemManagerClass))

typedef struct {
	GObject parent;
} NMModemManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*modem_added) (NMModemManager *manager, NMModem *modem, const char *driver);

	void (*modem_removed) (NMModemManager *manager, NMModem *modem);
} NMModemManagerClass;

GType nm_modem_manager_get_type (void);

NMModemManager *nm_modem_manager_get (void);

gboolean nm_modem_manager_has_modem_for_iface (NMModemManager *manager,
                                               const gchar *iface);

#endif /* NM_MODEM_MANAGER_H */
