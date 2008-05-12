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

#include "glocaldirectorymonitor.h"

enum
{
  PROP_0,
  PROP_DIRNAME
};

#if 0
static gboolean g_local_directory_monitor_cancel (GFileMonitor      *monitor);
static void     mounts_changed                   (GUnixMountMonitor *mount_monitor, 
                                                  gpointer           user_data);
#endif

G_DEFINE_ABSTRACT_TYPE (GLocalDirectoryMonitor, g_local_directory_monitor, G_TYPE_FILE_MONITOR)

static void
g_local_directory_monitor_finalize (GObject *object)
{
  GLocalDirectoryMonitor *local_monitor;
  local_monitor = G_LOCAL_DIRECTORY_MONITOR (object);

  g_free (local_monitor->dirname);

#if 0
  if (local_monitor->mount_monitor)
    {
      g_signal_handlers_disconnect_by_func (local_monitor->mount_monitor, mounts_changed, local_monitor);
      g_object_unref (local_monitor->mount_monitor);
      local_monitor->mount_monitor = NULL;
    }
#endif

  if (G_OBJECT_CLASS (g_local_directory_monitor_parent_class)->finalize)
    (*G_OBJECT_CLASS (g_local_directory_monitor_parent_class)->finalize) (object);
}

static void
g_local_directory_monitor_set_property (GObject      *object,
                                        guint         property_id,
                                        const GValue *value,
                                        GParamSpec   *pspec)
{
  switch (property_id)
  {
    case PROP_DIRNAME:
      /* Do nothing */
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
      break;
  }
}

static GObject *
g_local_directory_monitor_constructor (GType                  type,
                                       guint                  n_construct_properties,
                                       GObjectConstructParam *construct_properties)
{
  GObject *obj;
  GLocalDirectoryMonitorClass *klass;
  GObjectClass *parent_class;
  GLocalDirectoryMonitor *local_monitor;
  const gchar *dirname = NULL;
  gint i;
  
  klass = G_LOCAL_DIRECTORY_MONITOR_CLASS (g_type_class_peek (G_TYPE_LOCAL_DIRECTORY_MONITOR));
  parent_class = G_OBJECT_CLASS (g_type_class_peek_parent (klass));
  obj = parent_class->constructor (type,
                                   n_construct_properties,
                                   construct_properties);

  local_monitor = G_LOCAL_DIRECTORY_MONITOR (obj);

  for (i = 0; i < n_construct_properties; i++)
    {
      if (strcmp ("dirname", g_param_spec_get_name (construct_properties[i].pspec)) == 0)
        {
          if (!G_VALUE_HOLDS_STRING (construct_properties[i].value))
            g_warning ("%s: warning: construct_properties[i].value does not hold a string!", __func__);
          dirname = g_value_get_string (construct_properties[i].value);
          break;
        }
    }

  local_monitor->dirname = g_strdup (dirname);

#if 0
  if (!klass->mount_notify)
    {
#ifdef G_OS_WIN32
      g_warning ("G_OS_WIN32: no mount emulation");
#else
      GUnixMountEntry *mount;
      
      /* Emulate unmount detection */
      
      mount = g_unix_mount_at (local_monitor->dirname, NULL);
      
      local_monitor->was_mounted = mount != NULL;
      
      if (mount)
        g_unix_mount_free (mount);

      local_monitor->mount_monitor = g_unix_mount_monitor_new ();
      g_signal_connect_object (local_monitor->mount_monitor, "mounts_changed",
			       G_CALLBACK (mounts_changed), local_monitor, 0);
#endif
    }
#endif

  return obj;
}

static void
g_local_directory_monitor_class_init (GLocalDirectoryMonitorClass* klass)
{
  GObjectClass* gobject_class = G_OBJECT_CLASS (klass);
#if 0
  GFileMonitorClass *file_monitor_class = G_FILE_MONITOR_CLASS (klass);
#endif
  
  gobject_class->finalize = g_local_directory_monitor_finalize;
  gobject_class->set_property = g_local_directory_monitor_set_property;
  gobject_class->constructor = g_local_directory_monitor_constructor;

#if 0
  file_monitor_class->cancel = g_local_directory_monitor_cancel;
#endif

  g_object_class_install_property (gobject_class, 
                                   PROP_DIRNAME,
                                   g_param_spec_string ("dirname", 
                                                        "Directory name",
                                                        "Directory to monitor",
                                                        NULL, 
                                                        G_PARAM_CONSTRUCT_ONLY|
                                                        G_PARAM_WRITABLE|
                                                        G_PARAM_STATIC_NAME|G_PARAM_STATIC_NICK|G_PARAM_STATIC_BLURB));

#if 0
  klass->mount_notify = FALSE;
#endif
}

static void
g_local_directory_monitor_init (GLocalDirectoryMonitor *local_monitor)
{
}

#if 0
static void
mounts_changed (GUnixMountMonitor *mount_monitor,
                gpointer           user_data)
{
  GLocalDirectoryMonitor *local_monitor = user_data;
  GUnixMountEntry *mount;
  gboolean is_mounted;
  GFile *file;
  
  /* Emulate unmount detection */
#ifdef G_OS_WIN32
  mount = NULL;
  g_warning ("G_OS_WIN32: no mount emulation");
#else  
  mount = g_unix_mount_at (local_monitor->dirname, NULL);
  
  is_mounted = mount != NULL;
  
  if (mount)
    g_unix_mount_free (mount);
#endif

  if (local_monitor->was_mounted != is_mounted)
    {
      if (local_monitor->was_mounted && !is_mounted)
        {
          file = g_file_new_for_path (local_monitor->dirname);
          g_file_monitor_emit_event (G_FILE_MONITOR (local_monitor),
				     file, NULL,
				     G_FILE_MONITOR_EVENT_UNMOUNTED);
          g_object_unref (file);
        }
      local_monitor->was_mounted = is_mounted;
    }
}
#endif

/**
 * _g_local_directory_monitor_new:
 * @dirname: filename of the directory to monitor.
 * @flags: #GFileMonitorFlags.
 * 
 * Returns: new #GFileMonitor for the given @dirname.
 **/
GFileMonitor*
_g_local_directory_monitor_new (const char         *dirname,
				GFileMonitorFlags   flags,
				GError            **error)
{
  return G_FILE_MONITOR (g_object_new (G_TYPE_LOCAL_DIRECTORY_MONITOR, "dirname", dirname, NULL));
}

#if 0
static gboolean
g_local_directory_monitor_cancel (GFileMonitor *monitor)
{
  GLocalDirectoryMonitor *local_monitor = G_LOCAL_DIRECTORY_MONITOR (monitor);

  if (local_monitor->mount_monitor)
    {
      g_signal_handlers_disconnect_by_func (local_monitor->mount_monitor, mounts_changed, local_monitor);
      g_object_unref (local_monitor->mount_monitor);
      local_monitor->mount_monitor = NULL;
    }

  return TRUE;
}
#endif

