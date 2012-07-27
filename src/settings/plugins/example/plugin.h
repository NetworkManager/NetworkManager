/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service - example plugin
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef _PLUGIN_H_
#define _PLUGIN_H_

#include <glib-object.h>

/* GObject boilerplate: you usually only need to rename 'example' here to
 * your plugin's name.  These functions get used when casting pointers
 * to your plugin's object type.
 */
#define SC_TYPE_PLUGIN_EXAMPLE            (sc_plugin_example_get_type ())
#define SC_PLUGIN_EXAMPLE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SC_TYPE_PLUGIN_EXAMPLE, SCPluginExample))
#define SC_PLUGIN_EXAMPLE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SC_TYPE_PLUGIN_EXAMPLE, SCPluginExampleClass))
#define SC_IS_PLUGIN_EXAMPLE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SC_TYPE_PLUGIN_EXAMPLE))
#define SC_IS_PLUGIN_EXAMPLE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), SC_TYPE_PLUGIN_EXAMPLE))
#define SC_PLUGIN_EXAMPLE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SC_TYPE_PLUGIN_EXAMPLE, SCPluginExampleClass))

typedef struct {
	/* GObject instance structure for the plugin; we don't do anything special
	 * here so this object's instance is exactly the same as its parent.
	 */
	GObject parent;
} SCPluginExample;

typedef struct {
	/* GObject class structure; we don't do anything special here
	 * so this object's class is exactly the same as its parent.  Typically
	 * if the plugin implemented custom signals their prototypes would go
	 * here, but most plugins don't need to do this.
	 */
	GObjectClass parent;
} SCPluginExampleClass;

GType sc_plugin_example_get_type (void);

#endif	/* _PLUGIN_H_ */
