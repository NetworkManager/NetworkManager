/* GIO - GLib Input, Output and Streaming Library
 * 
 * Copyright (C) 2006-2007 Red Hat, Inc.
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
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: Alexander Larsson <alexl@redhat.com>
 */

#include <config.h>
#include <string.h>

#include "glocalfilemonitor.h"

enum
{
  PROP_0,
  PROP_FILENAME
};

G_DEFINE_ABSTRACT_TYPE (GLocalFileMonitor, g_local_file_monitor, G_TYPE_FILE_MONITOR)

static void
g_local_file_monitor_init (GLocalFileMonitor* local_monitor)
{
}

static void
g_local_file_monitor_set_property (GObject      *object,
                                   guint         property_id,
                                   const GValue *value,
                                   GParamSpec   *pspec)
{
  switch (property_id)
  {
    case PROP_FILENAME:
      /* Do nothing */
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static GObject *
g_local_file_monitor_constructor (GType                  type,
                                  guint                  n_construct_properties,
                                  GObjectConstructParam *construct_properties)
{
  GObject *obj;
  GLocalFileMonitorClass *klass;
  GObjectClass *parent_class;
  GLocalFileMonitor *local_monitor;
  const gchar *filename = NULL;
  gint i;
  
  klass = G_LOCAL_FILE_MONITOR_CLASS (g_type_class_peek (G_TYPE_LOCAL_FILE_MONITOR));
  parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
  obj = parent_class->constructor (type,
                                   n_construct_properties,
                                   construct_properties);

  local_monitor = G_LOCAL_FILE_MONITOR (obj);

  for (i = 0; i < n_construct_properties; i++)
    {
      if (strcmp ("filename", g_param_spec_get_name (construct_properties[i].pspec)) == 0)
        {
          g_warn_if_fail (G_VALUE_HOLDS_STRING (construct_properties[i].value));
          filename = g_value_get_string (construct_properties[i].value);
          break;
        }
    }

  g_warn_if_fail (filename != NULL);

  local_monitor->filename = g_strdup (filename);
  return obj;
}

static void
g_local_file_monitor_finalize (GObject *object)
{
  GLocalFileMonitor *local_monitor = G_LOCAL_FILE_MONITOR (object);
  if (local_monitor->filename)
    {
      g_free (local_monitor->filename);
      local_monitor->filename = NULL;
    }

  if (G_OBJECT_CLASS (g_local_file_monitor_parent_class)->finalize)
    (*G_OBJECT_CLASS (g_local_file_monitor_parent_class)->finalize) (object);
}

static void g_local_file_monitor_class_init (GLocalFileMonitorClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->set_property = g_local_file_monitor_set_property;
  gobject_class->finalize = g_local_file_monitor_finalize;
  gobject_class->constructor = g_local_file_monitor_constructor;

  g_object_class_install_property (gobject_class, 
                                   PROP_FILENAME,
                                   g_param_spec_string ("filename", 
                                                        "File name",
                                                        "File name to monitor",
                                                        NULL, 
                                                        G_PARAM_CONSTRUCT_ONLY|
                                                        G_PARAM_WRITABLE|
                                                        G_PARAM_STATIC_NAME|G_PARAM_STATIC_NICK|G_PARAM_STATIC_BLURB));
}

/**
 * g_local_file_monitor_new:
 * @pathname: path name to monitor.
 * @flags: #GFileMonitorFlags.
 * 
 * Returns: a new #GFileMonitor for the given @pathname. 
 **/
GFileMonitor*
_g_local_file_monitor_new (const char         *pathname,
			   GFileMonitorFlags   flags,
			   GError            **error)
{
  return G_FILE_MONITOR (g_object_new (G_TYPE_LOCAL_FILE_MONITOR, "filename", pathname, NULL));
}

