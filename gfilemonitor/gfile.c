/*
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Author: Dan Williams <dcbw@redhat.com>
 */

#include <glib-object.h>
#include <glib.h>

#include "gfile.h"
#include "glocalfilemonitor.h"
#include "glocaldirectorymonitor.h"

typedef struct {
	char *path;
} GFilePrivate;

#define G_FILE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), G_TYPE_FILE, GFilePrivate))

G_DEFINE_TYPE (GFile, g_file, G_TYPE_OBJECT)

char *
g_file_get_basename (GFile *file)
{
	g_return_val_if_fail (G_IS_FILE (file), NULL);

	return g_path_get_basename (G_FILE_GET_PRIVATE (file)->path);
}

char *
g_file_get_path (GFile *file)
{
	g_return_val_if_fail (G_IS_FILE (file), NULL);

	return g_strdup (G_FILE_GET_PRIVATE (file)->path);
}

const char *
g_file_get_const_path (GFile *file)
{
	g_return_val_if_fail (G_IS_FILE (file), NULL);

	return G_FILE_GET_PRIVATE (file)->path;
}

GFileMonitor *
g_file_monitor_directory (GFile *file,
                          GFileMonitorFlags flags,
                          void *unused,
                          GError **error)
{
	g_return_val_if_fail (G_IS_FILE (file), NULL);

	return _g_local_directory_monitor_new (G_FILE_GET_PRIVATE (file)->path, flags, error);
}

GFileMonitor *
g_file_monitor_file (GFile *file,
                     GFileMonitorFlags flags,
                     void *unused,
                     GError **error)
{
	g_return_val_if_fail (G_IS_FILE (file), NULL);

	return _g_local_file_monitor_new (G_FILE_GET_PRIVATE (file)->path, flags, error);
}

GFile *
g_file_new_for_path (const char *path)
{
	GFile *file;
	GFilePrivate *priv;

	file = (GFile *) g_object_new (G_TYPE_FILE, NULL);
	if (!file)
		return NULL;

	priv = G_FILE_GET_PRIVATE (file);
	priv->path = g_strdup (path);

	return file;
}

static void
g_file_init (GFile *file)
{
}

static void
finalize (GObject *object)
{
	GFile *file = G_FILE (object);
	GFilePrivate *priv = G_FILE_GET_PRIVATE (file);

	g_free (priv->path);
	priv->path = NULL;

	G_OBJECT_CLASS (g_file_parent_class)->finalize (object);
}

static void
g_file_class_init (GFileClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (GFilePrivate));

	/* virtual methods */
	object_class->finalize = finalize;
}

