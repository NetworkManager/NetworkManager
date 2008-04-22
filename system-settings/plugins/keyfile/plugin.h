/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include <glib-object.h>

#define SC_TYPE_PLUGIN_KEYFILE            (sc_plugin_keyfile_get_type ())
#define SC_PLUGIN_KEYFILE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_PLUGIN_KEYFILE, SCPluginKeyfile))
#define SC_PLUGIN_KEYFILE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_PLUGIN_KEYFILE, SCPluginKeyfileClass))
#define SC_IS_PLUGIN_KEYFILE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_PLUGIN_KEYFILE))
#define SC_IS_PLUGIN_KEYFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SC_TYPE_PLUGIN_KEYFILE))
#define SC_PLUGIN_KEYFILE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SC_TYPE_PLUGIN_KEYFILE, SCPluginKeyfileClass))

typedef struct {
	GObject parent;
} SCPluginKeyfile;

typedef struct {
	GObjectClass parent;
} SCPluginKeyfileClass;

GType sc_plugin_keyfile_get_type (void);

GQuark keyfile_plugin_error_quark (void);

#endif	/* _PLUGIN_H_ */
