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

#include "nm-default.h"

#define SETTINGS_TYPE_PLUGIN_IFNET            (settings_plugin_ifnet_get_type ())
#define SETTINGS_PLUGIN_IFNET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SETTINGS_TYPE_PLUGIN_IFNET, SettingsPluginIfnet))
#define SETTINGS_PLUGIN_IFNET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SETTINGS_TYPE_PLUGIN_IFNET, SettingsPluginIfnetClass))
#define SETTINGS_IS_PLUGIN_IFNET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SETTINGS_TYPE_PLUGIN_IFNET))
#define SETTINGS_IS_PLUGIN_IFNET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SETTINGS_TYPE_PLUGIN_IFNET))
#define SETTINGS_PLUGIN_IFNET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SETTINGS_TYPE_PLUGIN_IFNET, SettingsPluginIfnetClass))

typedef struct _SettingsPluginIfnet SettingsPluginIfnet;
typedef struct _SettingsPluginIfnetClass SettingsPluginIfnetClass;

struct _SettingsPluginIfnet {
	GObject parent;
};

struct _SettingsPluginIfnetClass {
	GObjectClass parent;
};

GType settings_plugin_ifnet_get_type (void);
#endif
