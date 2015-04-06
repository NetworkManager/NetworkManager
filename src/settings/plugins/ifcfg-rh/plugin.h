/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
 *
 * Dan Williams <dcbw@redhat.com>
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include "nm-glib.h"

#define SC_TYPE_PLUGIN_IFCFG            (sc_plugin_ifcfg_get_type ())
#define SC_PLUGIN_IFCFG(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfg))
#define SC_PLUGIN_IFCFG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgClass))
#define SC_IS_PLUGIN_IFCFG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_PLUGIN_IFCFG))
#define SC_IS_PLUGIN_IFCFG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_PLUGIN_IFCFG))
#define SC_PLUGIN_IFCFG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgClass))

typedef struct _SCPluginIfcfg SCPluginIfcfg;
typedef struct _SCPluginIfcfgClass SCPluginIfcfgClass;

struct _SCPluginIfcfg {
	GObject parent;
};

struct _SCPluginIfcfgClass {
	GObjectClass parent;
};

GType sc_plugin_ifcfg_get_type (void);

#endif	/* _PLUGIN_H_ */

