/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager system settings service (ifupdown)
 *
 * Alexander Sack <asac@ubuntu.com>
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
 * (C) Copyright 2008 Canonical Ltd.
 */

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include "nm-default.h"

#define PLUGIN_NAME "ifupdown"

#define SETTINGS_TYPE_PLUGIN_IFUPDOWN            (settings_plugin_ifupdown_get_type ())
#define SETTINGS_PLUGIN_IFUPDOWN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SETTINGS_TYPE_PLUGIN_IFUPDOWN, SettingsPluginIfupdown))
#define SETTINGS_PLUGIN_IFUPDOWN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SETTINGS_TYPE_PLUGIN_IFUPDOWN, SettingsPluginIfupdownClass))
#define SETTINGS_IS_PLUGIN_IFUPDOWN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SETTINGS_TYPE_PLUGIN_IFUPDOWN))
#define SETTINGS_IS_PLUGIN_IFUPDOWN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SETTINGS_TYPE_PLUGIN_IFUPDOWN))
#define SETTINGS_PLUGIN_IFUPDOWN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SETTINGS_TYPE_PLUGIN_IFUPDOWN, SettingsPluginIfupdownClass))

typedef struct _SettingsPluginIfupdown SettingsPluginIfupdown;
typedef struct _SettingsPluginIfupdownClass SettingsPluginIfupdownClass;

struct _SettingsPluginIfupdown {
	GObject parent;
};

struct _SettingsPluginIfupdownClass {
	GObjectClass parent;
};

GType settings_plugin_ifupdown_get_type (void);

#endif	/* _PLUGIN_H_ */
