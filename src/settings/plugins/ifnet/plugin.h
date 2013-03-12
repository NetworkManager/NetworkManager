/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service (ifnet)
 *
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include <glib-object.h>

#define SC_TYPE_PLUGIN_IFNET            (sc_plugin_ifnet_get_type ())
#define SC_PLUGIN_IFNET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_PLUGIN_IFNET, SCPluginIfnet))
#define SC_PLUGIN_IFNET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_PLUGIN_IFNET, SCPluginIfnetClass))
#define SC_IS_PLUGIN_IFNET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_PLUGIN_IFNET))
#define SC_IS_PLUGIN_IFNET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_PLUGIN_IFNET))
#define SC_PLUGIN_IFNET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SC_TYPE_PLUGIN_IFNET, SCPluginIfnetClass))

typedef struct _SCPluginIfnet SCPluginIfnet;
typedef struct _SCPluginIfnetClass SCPluginIfnetClass;

struct _SCPluginIfnet {
	GObject parent;
};

struct _SCPluginIfnetClass {
	GObjectClass parent;
};

GType sc_plugin_ifnet_get_type (void);
#endif
