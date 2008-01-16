/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SUPPLICANT_H
#define NM_SUPPLICANT_H 1

#include <glib/gtypes.h>
#include <glib-object.h>

#define NM_TYPE_SUPPLICANT            (nm_supplicant_get_type ())
#define NM_SUPPLICANT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SUPPLICANT, NMSupplicant))
#define NM_SUPPLICANT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SUPPLICANT, NMSupplicantClass))
#define NM_IS_SUPPLICANT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SUPPLICANT))
#define NM_IS_SUPPLICANT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SUPPLICANT))
#define NM_SUPPLICANT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SUPPLICANT, NMSupplicantClass))

typedef struct {
	GObject parent;
} NMSupplicant;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*state_changed) (NMSupplicant *supplicant,
					   gboolean connected);

	void (*down) (NMSupplicant *supplicant);
} NMSupplicantClass;

GType nm_supplicant_get_type (void);

NMSupplicant *nm_supplicant_new (void);
gboolean      nm_supplicant_exec (NMSupplicant *self,
						    GMainContext *ctx);

gboolean      nm_supplicant_interface_init (NMSupplicant *self, 
								    const char *iface,
								    const char *supplicant_driver);

gboolean      nm_supplicant_monitor_start  (NMSupplicant *self,
								    GMainContext *context,
								    guint32 timeout,
								    GSourceFunc timeout_cb,
								    gpointer user_data);

void          nm_supplicant_remove_timeout (NMSupplicant *self);

void          nm_supplicant_down           (NMSupplicant *self);

struct wpa_ctrl *nm_supplicant_get_ctrl     (NMSupplicant *self);


#endif /* NM_SUPPLICANT_H */
