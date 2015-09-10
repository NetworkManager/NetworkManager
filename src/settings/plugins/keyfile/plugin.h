/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - keyfile plugin
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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include "nm-default.h"

#define SETTINGS_TYPE_PLUGIN_KEYFILE            (settings_plugin_keyfile_get_type ())
#define SETTINGS_PLUGIN_KEYFILE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SETTINGS_TYPE_PLUGIN_KEYFILE, SettingsPluginKeyfile))
#define SETTINGS_PLUGIN_KEYFILE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SETTINGS_TYPE_PLUGIN_KEYFILE, SettingsPluginKeyfileClass))
#define SETTINGS_IS_PLUGIN_KEYFILE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SETTINGS_TYPE_PLUGIN_KEYFILE))
#define SETTINGS_IS_PLUGIN_KEYFILE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SETTINGS_TYPE_PLUGIN_KEYFILE))
#define SETTINGS_PLUGIN_KEYFILE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SETTINGS_TYPE_PLUGIN_KEYFILE, SettingsPluginKeyfileClass))

typedef struct {
	GObject parent;
} SettingsPluginKeyfile;

typedef struct {
	GObjectClass parent;
} SettingsPluginKeyfileClass;

GType settings_plugin_keyfile_get_type (void);

GObject *nm_settings_keyfile_plugin_new (void);

#endif	/* _PLUGIN_H_ */
