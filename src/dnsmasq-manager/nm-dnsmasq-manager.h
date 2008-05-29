/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_DNSMASQ_MANAGER_H
#define NM_DNSMASQ_MANAGER_H

#include <glib/gtypes.h>
#include <glib-object.h>

#define NM_TYPE_DNSMASQ_MANAGER            (nm_dnsmasq_manager_get_type ())
#define NM_DNSMASQ_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManager))
#define NM_DNSMASQ_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManagerClass))
#define NM_IS_DNSMASQ_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DNSMASQ_MANAGER))
#define NM_IS_DNSMASQ_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DNSMASQ_MANAGER))
#define NM_DNSMASQ_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DNSMASQ_MANAGER, NMDnsMasqManagerClass))

typedef enum {
	NM_DNSMASQ_STATUS_UNKNOWN,

	NM_DNSMASQ_STATUS_DEAD,
	NM_DNSMASQ_STATUS_RUNNING,
} NMDnsMasqStatus;

typedef struct {
	GObject parent;
} NMDnsMasqManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*state_changed) (NMDnsMasqManager *manager, NMDnsMasqStatus status);
} NMDnsMasqManagerClass;

GType nm_dnsmasq_manager_get_type (void);

NMDnsMasqManager *nm_dnsmasq_manager_new (void);

gboolean nm_dnsmasq_manager_start (NMDnsMasqManager *manager,
                                   const char *device,
                                   GError **err);

void     nm_dnsmasq_manager_stop  (NMDnsMasqManager *manager);

#define NM_DNSMASQ_MANAGER_ERROR nm_dnsmasq_manager_error_quark()
#define NM_TYPE_DNSMASQ_MANAGER_ERROR (nm_dnsmasq_manager_error_get_type ()) 

GQuark nm_dnsmasq_manager_error_quark (void);

#endif /* NM_DNSMASQ_MANAGER_H */
