/*
 *  Copyright (C) 2006 Red Hat, Inc.
 *
 *  Written by Dan Williams <dcbw@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <glib.h>
#include <dbus/dbus.h>
#include "nm-supplicant-manager.h"

#define NM_SUPPLICANT_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                              NM_TYPE_SUPPLICANT_MANAGER, \
                                              NMSupplicantManagerPrivate))

struct _NMSupplicantManagerPrivate {
	gboolean	running;
	gboolean	dispose_has_run;
};


NMSupplicantManager *
nm_supplicant_manager_new (void)
{
	NMSupplicantManager * mgr;

	mgr = g_object_new (NM_TYPE_SUPPLICANT_MANAGER, NULL);
	return mgr;
}

static void
nm_supplicant_manager_init (NMSupplicantManager * self)
{
	self->priv = NM_SUPPLICANT_MANAGER_GET_PRIVATE (self);
	self->priv->running = FALSE;
	self->priv->dispose_has_run = FALSE;
}

static void
nm_supplicant_manager_class_init (NMSupplicantManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

/*
	object_class->dispose = nm_supplicant_manager_dispose;
	object_class->finalize = nm_supplicant_manager_finalize;
*/

	g_type_class_add_private (object_class, sizeof (NMSupplicantManagerPrivate));
}

GType
nm_supplicant_manager_get_type (void)
{
	static GType type = 0;
	if (type == 0) {
		static const GTypeInfo info = {
			sizeof (NMSupplicantManagerClass),
			NULL,	/* base_init */
			NULL,	/* base_finalize */
			(GClassInitFunc) nm_supplicant_manager_class_init,
			NULL,	/* class_finalize */
			NULL,	/* class_data */
			sizeof (NMSupplicantManager),
			0,		/* n_preallocs */
			(GInstanceInitFunc) nm_supplicant_manager_init,
			NULL		/* value_table */
		};

		type = g_type_register_static (G_TYPE_OBJECT,
								 "NMSupplicantManager",
								 &info, 0);
	}
	return type;
}
